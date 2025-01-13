use crate::suite::constants::LENGTH_G1_POINT;
use crate::utils::serialize::{Deserialize, Serialize};
use bls12_381::{G1Affine, Scalar};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_signature() {
        let signature = Signature {
            a: G1Affine::generator(),
            e: Scalar::from(11451419198101141145) * Scalar::from(14191981011451419198),
        };
        let serialized = signature.serialize();
        let deserialized = Signature::deserialize(&serialized);

        assert_eq!(signature, deserialized);
    }
}
