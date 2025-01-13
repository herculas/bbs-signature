use crate::suite::cipher::Cipher;
use crate::suite::constants::{
    PADDING_MSG_GENERATOR_SEED, PADDING_SIG_GENERATOR_DST, PADDING_SIG_GENERATOR_SEED,
};
use crate::utils::format::{concat_bytes, i2osp};
use bls12_381::G1Affine;

/// Create a set of randomly sampled points from the G1 group, called the generators.
///
/// This operation makes use of the `expand_message` and `hash_to_curve` primitives to hash a seed
/// to a set of generators. These primitives are implicitly defined by the `Cipher` trait.
///
/// - `count`: the number of generators to create.
/// - `api_id`: the API identifier to use for the hash function, if not specified, it defaults to
///             an empty array.
/// - `cipher`: the cipher suite.
///
/// Return a vector of `G1Affine` points.
pub fn create_generator(count: usize, api_id: Option<&[u8]>, cipher: &Cipher) -> Vec<G1Affine> {
    let seed_dst = concat_bytes(&[api_id.unwrap_or(&[]), PADDING_SIG_GENERATOR_SEED]);
    let generator_dst = concat_bytes(&[api_id.unwrap_or(&[]), PADDING_SIG_GENERATOR_DST]);
    let generator_seed = concat_bytes(&[api_id.unwrap_or(&[]), PADDING_MSG_GENERATOR_SEED]);

    let mut generators = Vec::with_capacity(count);
    let mut v = (cipher.expand_message)(&generator_seed, &seed_dst, None);

    for i in 1..=count {
        v = (cipher.expand_message)(&concat_bytes(&[&v, &i2osp(i as u64, 8)]), &seed_dst, None);
        generators.push((cipher.hash_to_curve)(&v, &generator_dst));
    }

    generators
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::constants::PADDING_API_ID;
    use crate::suite::instance::{BLS12_381_G1_XMD_SHA_256, BLS12_381_G1_XOF_SHAKE_256};
    use crate::utils::format::bytes_to_hex;

    #[test]
    fn shake_256_message_generators() {
        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let api_id = concat_bytes(&[cipher.id, PADDING_API_ID]);
        let generators = create_generator(11, Some(&api_id), &cipher);

        let q_1 = bytes_to_hex(&generators[0].to_compressed());
        let h_1 = bytes_to_hex(&generators[1].to_compressed());
        let h_2 = bytes_to_hex(&generators[2].to_compressed());
        let h_3 = bytes_to_hex(&generators[3].to_compressed());
        let h_4 = bytes_to_hex(&generators[4].to_compressed());
        let h_5 = bytes_to_hex(&generators[5].to_compressed());
        let h_6 = bytes_to_hex(&generators[6].to_compressed());
        let h_7 = bytes_to_hex(&generators[7].to_compressed());
        let h_8 = bytes_to_hex(&generators[8].to_compressed());
        let h_9 = bytes_to_hex(&generators[9].to_compressed());
        let h_10 = bytes_to_hex(&generators[10].to_compressed());

        assert_eq!(
            q_1,
            "\
            a9d40131066399fd41af51d883f4473b0dcd7d028d3d34ef\
            17f3241d204e28507d7ecae032afa1d5490849b7678ec1f8"
        );
        assert_eq!(
            h_1,
            "\
        903c7ca0b7e78a2017d0baf74103bd00ca8ff9bf429f834f\
        071c75ffe6bfdec6d6dca15417e4ac08ca4ae1e78b7adc0e"
        );
        assert_eq!(
            h_2,
            "\
        84321f5855bfb6b001f0dfcb47ac9b5cc68f1a4edd20f0ec\
        850e0563b27d2accee6edff1a26b357762fb24e8ddbb6fcb"
        );
        assert_eq!(
            h_3,
            "\
        b3060dff0d12a32819e08da00e61810676cc9185fdd750e5\
        ef82b1a9798c7d76d63de3b6225d6c9a479d6c21a7c8bf93"
        );
        assert_eq!(
            h_4,
            "\
        8f1093d1e553cdead3c70ce55b6d664e5d1912cc9edfdd37\
        bf1dad11ca396a0a8bb062092d391ebf8790ea5722413f68"
        );
        assert_eq!(
            h_5,
            "\
        990824e00b48a68c3d9a308e8c52a57b1bc84d1cf5d3c0f8\
        c6fb6b1230e4e5b8eb752fb374da0b1ef687040024868140"
        );
        assert_eq!(
            h_6,
            "\
        b86d1c6ab8ce22bc53f625d1ce9796657f18060fcb1893ce\
        8931156ef992fe56856199f8fa6c998e5d855a354a26b0dd"
        );
        assert_eq!(
            h_7,
            "\
        b4cdd98c5c1e64cb324e0c57954f719d5c5f9e8d991fd8e1\
        59b31c8d079c76a67321a30311975c706578d3a0ddc313b7"
        );
        assert_eq!(
            h_8,
            "\
        8311492d43ec9182a5fc44a75419b09547e311251fe38b68\
        64dc1e706e29446cb3ea4d501634eb13327245fd8a574f77"
        );
        assert_eq!(
            h_9,
            "\
        ac00b493f92d17837a28d1f5b07991ca5ab9f370ae40d4f9\
        b9f2711749ca200110ce6517dc28400d4ea25dddc146cacc"
        );
        assert_eq!(
            h_10,
            "\
        965a6c62451d4be6cb175dec39727dc665762673ee42bf0\
        ac13a37a74784fbd61e84e0915277a6f59863b2bb4f5f6005"
        );
    }

    #[test]
    fn sha_256_message_generators() {
        let cipher = BLS12_381_G1_XMD_SHA_256;
        let api_id = concat_bytes(&[cipher.id, PADDING_API_ID]);
        let generators = create_generator(11, Some(&api_id), &cipher);

        let q_1 = bytes_to_hex(&generators[0].to_compressed());
        let h_1 = bytes_to_hex(&generators[1].to_compressed());
        let h_2 = bytes_to_hex(&generators[2].to_compressed());
        let h_3 = bytes_to_hex(&generators[3].to_compressed());
        let h_4 = bytes_to_hex(&generators[4].to_compressed());
        let h_5 = bytes_to_hex(&generators[5].to_compressed());
        let h_6 = bytes_to_hex(&generators[6].to_compressed());
        let h_7 = bytes_to_hex(&generators[7].to_compressed());
        let h_8 = bytes_to_hex(&generators[8].to_compressed());
        let h_9 = bytes_to_hex(&generators[9].to_compressed());
        let h_10 = bytes_to_hex(&generators[10].to_compressed());

        assert_eq!(
            q_1,
            "\
        a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48\
        fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be"
        );
        assert_eq!(
            h_1,
            "\
        98cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38\
        df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d4"
        );
        assert_eq!(
            h_2,
            "\
        a31fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e7375\
        07e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a"
        );
        assert_eq!(
            h_3,
            "\
        b479263445f4d2108965a9086f9d1fdc8cde77d14a91c856\
        769521ad3344754cc5ce90d9bc4c696dffbc9ef1d6ad1b62"
        );
        assert_eq!(
            h_4,
            "\
        ac0401766d2128d4791d922557c7b4d1ae9a9b508ce26657\
        5244a8d6f32110d7b0b7557b77604869633bb49afbe20035"
        );
        assert_eq!(
            h_5,
            "\
        b95d2898370ebc542857746a316ce32fa5151c31f9b57915\
        e308ee9d1de7db69127d919e984ea0747f5223821b596335"
        );
        assert_eq!(
            h_6,
            "\
        8f19359ae6ee508157492c06765b7df09e2e5ad591115742\
        f2de9c08572bb2845cbf03fd7e23b7f031ed9c7564e52f39"
        );
        assert_eq!(
            h_7,
            "\
        abc914abe2926324b2c848e8a411a2b6df18cbe7758db864\
        4145fefb0bf0a2d558a8c9946bd35e00c69d167aadf304c1"
        );
        assert_eq!(
            h_8,
            "\
        80755b3eb0dd4249cbefd20f177cee88e0761c066b717948\
        25c9997b551f24051c352567ba6c01e57ac75dff763eaa17"
        );
        assert_eq!(
            h_9,
            "\
        82701eb98070728e1769525e73abff1783cedc364adb20c0\
        5c897a62f2ab2927f86f118dcb7819a7b218d8f3fee4bd7f"
        );
        assert_eq!(
            h_10,
            "\
        a1f229540474f4d6f1134761b92b788128c7ac8dc9b0c52\
        d59493132679673032ac7db3fb3d79b46b13c1c41ee495bca"
        );
    }
}
