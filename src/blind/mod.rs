use crate::suite::constants::{LENGTH_G1_POINT, LENGTH_SCALAR};
use crate::utils::serialize::{Deserialize, Serialize};
use bls12_381::{G1Affine, Scalar};

mod commitment;
mod core;
pub(crate) mod interface;

// TODO: split into proof and signature
// TODO: name cover

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

/// Serialize a commitment along with the proof-of-correctness of it.
///
/// - `commitment`: a point of G1 group.
/// - `proof`: a commitment proof, containing a scalar, a vector of scalars, and another scalar, in thar order.
///
/// Return an octet string representing the serialized commitment and proof.
pub(crate) fn commitment_with_proof_to_octets(
    commitment: &G1Affine,
    proof: &CommitmentProof,
) -> Vec<u8> {
    // Procedure:
    //
    // 1. commitment_octets := serialize(commitment).
    // 2. If commitment_octets is INVALID, return INVALID.
    // 3. proof_octets := serialize(proof).
    // 4. If proof_octets is INVALID, return INVALID.
    // 5. Return commitment_octets || proof_octets.

    let mut serialized = Vec::new();
    serialized.extend_from_slice(&commitment.serialize());
    serialized.extend_from_slice(&proof.serialize());
    serialized
}

/// Deserialize an octet string to a commitment along with the proof-of-correctness of it.
///
/// - `commitment_with_proof_octets`: an octet string representing the serialized commitment and proof.
///
/// Return a tuple of a commitment and a commitment proof, where the commitment is a point in G1 group, and the proof
/// is a commitment proof, containing a scalar, a vector of scalars, and another scalar, in thar order.
pub(crate) fn octets_to_commitment_with_proof(
    commitment_octets: &[u8],
) -> (G1Affine, CommitmentProof) {
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
    if commitment_octets.len() < commit_len_floor {
        panic!("The length of commitment octets is less than the floor length.");
    }

    let c_octets = &commitment_octets[..LENGTH_G1_POINT];
    let c = G1Affine::deserialize(c_octets);
    if c == G1Affine::identity() {
        panic!("The commitment is the identity element of G1 group.");
    }

    let proof_octets = &commitment_octets[LENGTH_G1_POINT..];
    let proof = CommitmentProof::deserialize(proof_octets);

    (c, proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blind::CommitmentProof;
    use crate::utils::scalar::random_scalar;
    use crate::utils::serialize::Serialize;
    use getrandom::getrandom;
    use std::usize;

    #[test]
    fn proof_serialization() {
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

    #[test]
    fn proof_and_commitment_serialization() {
        let mut buf = [0u8; 2];
        getrandom(&mut buf).unwrap();
        let number = buf[0] as usize;

        let s_hat = random_scalar();
        let challenge = random_scalar();

        let mut m_hats = Vec::new();
        for _ in 1..number {
            m_hats.push(random_scalar());
        }

        let commitment: G1Affine = (G1Affine::generator() * random_scalar()).into();
        let proof = CommitmentProof {
            s_hat,
            m_hats,
            challenge,
        };

        let serialized = commitment_with_proof_to_octets(&commitment, &proof);
        let (des_commitment, des_proof) = octets_to_commitment_with_proof(&serialized);
        assert_eq!(commitment, des_commitment);
        assert_eq!(proof, des_proof);
    }
}
