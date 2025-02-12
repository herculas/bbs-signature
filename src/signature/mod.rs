use crate::suite::constants::{LENGTH_G1_POINT, LENGTH_SCALAR};

use crate::utils::format::{bytes_to_hex, hex_to_bytes};
use crate::utils::serialize::{Deserialize, Export, Import, Serialize};

use bls12_381::{G1Affine, Scalar};
use wasm_bindgen::JsValue;

pub mod core;
pub(crate) mod interface;
mod subroutine;

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

/// A zero-knowledge proof-of-correctness of a commitment, consisting of a scalar value, a possibly empty set of scalars
/// (of length equal to the number of committed messages), and another scalar, in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitmentProof {
    s_hat: Scalar,
    m_hats: Vec<Scalar>,
    challenge: Scalar,
}

impl Serialize for CommitmentProof {
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.s_hat.serialize());
        for m_hat in &self.m_hats {
            serialized.extend_from_slice(&m_hat.serialize());
        }
        serialized.extend_from_slice(&self.challenge.serialize());
        serialized
    }
}

impl Deserialize for CommitmentProof {
    fn deserialize(bytes: &[u8]) -> Self {
        let s_hat = Scalar::deserialize(&bytes[..LENGTH_SCALAR]);

        let mut m_hats = Vec::new();
        let mut offset = LENGTH_SCALAR;
        while offset + LENGTH_SCALAR < bytes.len() {
            m_hats.push(Scalar::deserialize(&bytes[offset..offset + LENGTH_SCALAR]));
            offset += LENGTH_SCALAR;
        }

        let challenge = Scalar::deserialize(&bytes[offset..]);
        Self {
            s_hat,
            m_hats,
            challenge,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::scalar::random_scalar;
    use getrandom::getrandom;

    #[test]
    fn serialize_signature() {
        let signature = Signature {
            a: (G1Affine::generator() * random_scalar()).into(),
            e: random_scalar(),
        };
        let serialized = signature.serialize();
        let deserialized = Signature::deserialize(&serialized);

        assert_eq!(signature, deserialized);
    }

    #[test]
    fn serialize_commitment_proof() {
        let mut buf = [0u8; 2];
        getrandom(&mut buf).unwrap();
        let number = buf[0] as usize;

        let s_hat = random_scalar();
        let challenge = random_scalar();

        let mut m_hats = Vec::new();
        for _ in 1..number {
            m_hats.push(random_scalar());
        }

        let proof = CommitmentProof {
            s_hat,
            m_hats,
            challenge,
        };

        let serialized = proof.serialize();
        let deserialized = CommitmentProof::deserialize(&serialized);
        assert_eq!(proof, deserialized);
    }
}
