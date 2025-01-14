use crate::suite::cipher::Cipher;
use crate::utils::format::i2osp;
use crate::utils::scalar::hash_to_scalar;
use bls12_381::{G2Affine, Scalar};
use crate::suite::constants::PADDING_KEYGEN_DST;

/// Generate a secret key deterministically from the given material and info.
///
/// - `key_material`: a secret octet string from which the secret key is derived, at least 32 bytes.
/// - `key_info`: context-specific information to bind the secret key to a particular context. If not specified, it is
///         set to an empty string.
/// - `key_dst`: an octet string representing the domain separation tag. If not specified, it is set to 
///         "<cipher_suite_id> || KEYGEN_DST_".
/// - `cipher`: the cipher suite to use.
///
/// Return a scalar as the secret key.
pub fn generate_secret_key(
    key_material: &[u8],
    key_info: Option<&[u8]>,
    key_dst: Option<&[u8]>,
    cipher: &Cipher,
) -> Scalar {
    let inner_key_info = key_info.unwrap_or(&[]);
    let default_inner = [cipher.id, PADDING_KEYGEN_DST].concat();
    let inner_key_dst = key_dst.unwrap_or(default_inner.as_slice());

    // Procedure:
    //
    // 1. If len(key_material) < 32, return INVALID.
    // 2. If len(key_info) > 65535, return INVALID.
    // 3. derive_input := key_material || i2osp(len(key_info), 2) || key_info.
    // 4. secret_key := hash_to_scalar(derive_input, key_dst).
    // 5. Return secret_key.
    if key_material.len() < 32 {
        panic!("key_material must be at least 32 bytes");
    }
    if inner_key_info.len() > 65535 {
        panic!("key_info must be at most 65535 bytes");
    }
    let derive_input = [
        key_material,
        i2osp(inner_key_info.len() as u64, 2).as_slice(),
        inner_key_info,
    ]
        .concat();
    hash_to_scalar(&derive_input, inner_key_dst, cipher)
}

/// Derive a public key from the given secret key.
///
/// - `secret_key`: the secret key to derive the public key from.
/// - `cipher`: the cipher suite to use.
///
/// Return an octet string as the public key.
pub fn derive_public_key(secret_key: &Scalar) -> [u8; 96] {
    // Procedure:
    //
    // 1. W := secret_key * BP2.
    // 2. Return point_to_octets_E2(W).
    let w: G2Affine = (G2Affine::generator() * secret_key).into();
    w.to_compressed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::instance::{BLS12_381_G1_XMD_SHA_256, BLS12_381_G1_XOF_SHAKE_256};
    use crate::utils::format::{bytes_to_hex, hex_to_bytes};

    #[test]
    fn shake_256_key_generation() {
        let material = hex_to_bytes(
            "\
            746869732d49532d6a7573742d616e2d546573742d494b4d\
            2d746f2d67656e65726174652d246528724074232d6b6579",
        );
        let info = hex_to_bytes(
            "\
            746869732d49532d736f6d652d6b65792d6d657461646174\
            612d746f2d62652d757365642d696e2d746573742d6b6579\
            2d67656e",
        );
        let dst = hex_to_bytes(
            "\
            4242535f424c53313233383147315f584f463a5348414b45\
            2d3235365f535357555f524f5f4832475f484d32535f4b45\
            5947454e5f4453545f",
        );

        let cipher = BLS12_381_G1_XOF_SHAKE_256;
        let secret_key = generate_secret_key(&material, Some(&info), Some(&dst), &cipher);
        let public_key = derive_public_key(&secret_key);

        assert_eq!(
            secret_key.to_string(),
            "0x\
                2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
        );
        assert_eq!(
            bytes_to_hex(&public_key),
            "\
                92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1\
                8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179\
                eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"
        );
    }

    #[test]
    fn sha_256_key_generation() {
        let material = hex_to_bytes(
            "\
            746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65\
            726174652d246528724074232d6b6579",
        );
        let info = hex_to_bytes(
            "\
            746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d\
            757365642d696e2d746573742d6b65792d67656e",
        );
        let dst = hex_to_bytes(
            "\
            4242535f424c53313233383147315f584d443a5348412d3235365f535357555f\
            524f5f4832475f484d32535f4b455947454e5f4453545f",
        );

        let cipher = BLS12_381_G1_XMD_SHA_256;
        let secret_key = generate_secret_key(&material, Some(&info), Some(&dst), &cipher);
        let public_key = derive_public_key(&secret_key);

        assert_eq!(
            secret_key.to_string(),
            "0x\
                60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
        );
        assert_eq!(
            bytes_to_hex(&public_key),
            "\
                a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28\
                51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f\
                1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"
        );
    }
}
