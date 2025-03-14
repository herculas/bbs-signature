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
pub(crate) struct BlindProof {
    s_hat: Scalar,
    m_hats: Vec<Scalar>,
    challenge: Scalar,
}

impl Serialize for BlindProof {
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

impl Deserialize for BlindProof {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitmentWithProof {
    commitment: G1Affine,
    proof: BlindProof,
}

impl Serialize for CommitmentWithProof {
    fn serialize(&self) -> Vec<u8> {
        // Procedure:
        //
        // 1. commitment_octets := serialize(commitment).
        // 2. If commitment_octets is INVALID, return INVALID.
        // 3. proof_octets := serialize(proof).
        // 4. If proof_octets is INVALID, return INVALID.
        // 5. Return commitment_octets || proof_octets.

        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.commitment.serialize());
        serialized.extend_from_slice(&self.proof.serialize());
        serialized
    }
}

impl Deserialize for CommitmentWithProof {
    fn deserialize(bytes: &[u8]) -> Self {
        // Procedure:
        //
        // 1. commit_len_floor := octet_point_length + 2 * octet_scalar_length.
        // 2. If len(commitment_octets) < commit_len_floor, return INVALID.
        // 3. c_octets := commitment_octets[0..(octet_point_length - 1)].
        // 4. c := octets_to_point_g1(c_octets).
        // 5. If c is INVALID, return INVALID.
        // 6. If c == Identity_G1, return INVALID.
        //
        // 7. j := 0.
        // 8. index := octet_point_length.
        // 9. While index < len(commitment_octets):
        // 10.      end_index := index + octet_scalar_length - 1.
        // 11.      s_j := OS2IP(commitment_octets[index..end_index]).
        // 12.      If s_j == 0 or s_j >= r, return INVALID.
        // 13.      index += octet_scalar_length.
        // 14.      j += 1.
        //
        // 15. If index != len(commitment_octets), return INVALID.
        // 16. If j < 2, return INVALID.
        // 17. msg_commitment := [].
        // 18. If j >= 3, set msg_commitment := (s_2, s_3, ..., s_{j-1}).
        // 19. Return (c, (s_0, msg_commitment, s_j)).

        let commit_len_floor = LENGTH_G1_POINT + 2 * LENGTH_SCALAR;
        if bytes.len() < commit_len_floor {
            panic!("The length of commitment octets is less than the floor length.");
        }

        let commitment_octets = &bytes[..LENGTH_G1_POINT];
        let commitment = G1Affine::deserialize(commitment_octets);
        if commitment == G1Affine::identity() {
            panic!("The commitment is the identity element of G1 group.");
        }

        let proof_octets = &bytes[LENGTH_G1_POINT..];
        let proof = BlindProof::deserialize(proof_octets);

        Self { commitment, proof }
    }
}

pub(crate) fn export_blindness(
    commitment_with_proof: &CommitmentWithProof,
    prover_blind: &Scalar,
) -> JsValue {
    let mut serialized = Vec::new();
    serialized.extend_from_slice(&commitment_with_proof.serialize());
    serialized.extend_from_slice(&prover_blind.serialize());
    JsValue::from_str(&bytes_to_hex(&serialized))
}
