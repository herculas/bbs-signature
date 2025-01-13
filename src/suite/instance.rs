use crate::suite::cipher::Cipher;
use crate::suite::constants::LENGTH_MESSAGE_EXPAND;
use bls12_381::hash_to_curve::{
    ExpandMessageState, ExpandMsgXmd, ExpandMsgXof, HashToCurve, InitExpandMessage,
};
use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Prepared, Gt};
use sha2::Sha256;
use sha3::Shake256;

pub const BLS12_381_G1_XOF_SHAKE_256: Cipher = Cipher {
    id: b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_",
    singularity: [
        0x89, 0x29, 0xdf, 0xbc, 0x7e, 0x66, 0x42, 0xc4, 0xed, 0x9c, 0xba, 0x08, 0x56, 0xe4, 0x93,
        0xf8, 0xb9, 0xd7, 0xd5, 0xfc, 0xb0, 0xc3, 0x1e, 0xf8, 0xfd, 0xcd, 0x34, 0xd5, 0x06, 0x48,
        0xa5, 0x6c, 0x79, 0x5e, 0x10, 0x6e, 0x9e, 0xad, 0xa6, 0xe0, 0xbd, 0xa3, 0x86, 0xb4, 0x14,
        0x15, 0x07, 0x55,
    ],
    hash_to_curve: |message: &[u8], dst: &[u8]| {
        if dst.len() > 255 {
            panic!("dst length must be less than 255");
        }
        <G1Projective as HashToCurve<ExpandMsgXof<Shake256>>>::hash_to_curve(message, dst).into()
    },
    expand_message: |message: &[u8], dst: &[u8], expand_length: Option<usize>| {
        if dst.len() > 255 {
            panic!("dst length must be less than 255");
        }
        ExpandMsgXof::<Shake256>::init_expand(message, dst, expand_length.unwrap_or(LENGTH_MESSAGE_EXPAND))
            .into_vec()
    },
    pairing_compare: |terms: &[(&G1Affine, &G2Prepared)], result: &Gt| {
        multi_miller_loop(terms).final_exponentiation() == *result
    },
};

pub const BLS12_381_G1_XMD_SHA_256: Cipher = Cipher {
    id: b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_",
    singularity: [
        0xa8, 0xce, 0x25, 0x61, 0x02, 0x84, 0x08, 0x21, 0xa3, 0xe9, 0x4e, 0xa9, 0x02, 0x5e, 0x46,
        0x62, 0xb2, 0x05, 0x76, 0x2f, 0x97, 0x76, 0xb3, 0xa7, 0x66, 0xc8, 0x72, 0xb9, 0x48, 0xf1,
        0xfd, 0x22, 0x5e, 0x7c, 0x59, 0x69, 0x85, 0x88, 0xe7, 0x0d, 0x11, 0x40, 0x6d, 0x16, 0x1b,
        0x4e, 0x28, 0xc9,
    ],
    hash_to_curve: |message: &[u8], dst: &[u8]| {
        if dst.len() > 255 {
            panic!("dst length must be less than 255");
        }
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, dst).into()
    },
    expand_message: |message: &[u8], dst: &[u8], expand_length: Option<usize>| {
        if dst.len() > 255 {
            panic!("dst length must be less than 255");
        }
        ExpandMsgXmd::<Sha256>::init_expand(message, dst, expand_length.unwrap_or(LENGTH_MESSAGE_EXPAND))
            .into_vec()
    },
    pairing_compare: |terms: &[(&G1Affine, &G2Prepared)], result: &Gt| {
        multi_miller_loop(terms).final_exponentiation() == *result
    },
};
