use crate::suite::constants::LENGTH_G1_POINT;
use crate::utils::format::{bytes_to_hex, hex_to_bytes};
use crate::utils::serialize::{Deserialize, Export, Import, Serialize};
use bls12_381::{G1Affine, Scalar};
use wasm_bindgen::JsValue;

mod core;
mod interface;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Signature {
    pub(crate) a: G1Affine,
    pub(crate) e: Scalar,
}

impl Serialize for Signature {
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.a.serialize());
        serialized.extend_from_slice(&self.e.serialize());
        serialized
    }
}

impl Deserialize for Signature {
    fn deserialize(bytes: &[u8]) -> Self {
        let a = G1Affine::deserialize(&bytes[..LENGTH_G1_POINT]);
        let e = Scalar::deserialize(&bytes[LENGTH_G1_POINT..]);
        Signature { a, e }
    }
}

impl Export for Signature {
    fn export(&self) -> JsValue {
        JsValue::from_str(&bytes_to_hex(&self.serialize()))
    }
}

impl Import for Signature {
    fn import(source: &JsValue) -> Self {
        Signature::deserialize(&hex_to_bytes(&source.as_string().unwrap()))
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use ff::Field;
//     use rand_core::OsRng;
// 
//     #[test]
//     fn test_serialize_signature() {
//         let signature = Signature {
//             a: (G1Affine::generator() * Scalar::random(&mut OsRng)).into(),
//             e: Scalar::random(&mut OsRng),
//         };
//         let serialized = signature.serialize();
//         let deserialized = Signature::deserialize(&serialized);
// 
//         assert_eq!(signature, deserialized);
//     }
// }
