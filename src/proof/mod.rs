use crate::suite::constants::{LENGTH_G1_POINT, LENGTH_SCALAR};

use crate::utils::format::{bytes_to_hex, hex_to_bytes};
use crate::utils::serialize::{Deserialize, Export, Import, Serialize};

use bls12_381::{G1Affine, Scalar};
use wasm_bindgen::JsValue;

mod core;
pub(crate) mod interface;
mod subroutine;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreProof {
    a_bar: G1Affine,
    b_bar: G1Affine,
    d: G1Affine,
    t_1: G1Affine,
    t_2: G1Affine,
    domain: Scalar,
}

impl Serialize for PreProof {
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.a_bar.serialize());
        serialized.extend_from_slice(&self.b_bar.serialize());
        serialized.extend_from_slice(&self.d.serialize());
        serialized.extend_from_slice(&self.t_1.serialize());
        serialized.extend_from_slice(&self.t_2.serialize());
        serialized.extend_from_slice(&self.domain.serialize());
        serialized
    }
}

impl Deserialize for PreProof {
    fn deserialize(bytes: &[u8]) -> Self {
        let a_bar = G1Affine::deserialize(&bytes[..LENGTH_G1_POINT]);
        let b_bar = G1Affine::deserialize(&bytes[LENGTH_G1_POINT..LENGTH_G1_POINT * 2]);
        let d = G1Affine::deserialize(&bytes[LENGTH_G1_POINT * 2..LENGTH_G1_POINT * 3]);
        let t_1 = G1Affine::deserialize(&bytes[LENGTH_G1_POINT * 3..LENGTH_G1_POINT * 4]);
        let t_2 = G1Affine::deserialize(&bytes[LENGTH_G1_POINT * 4..LENGTH_G1_POINT * 5]);
        let domain = Scalar::deserialize(&bytes[LENGTH_G1_POINT * 5..]);
        PreProof {
            a_bar,
            b_bar,
            d,
            t_1,
            t_2,
            domain,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudonymProof {
    pseudonym: G1Affine,
    op: G1Affine,
    ut: G1Affine,
}

impl Serialize for PseudonymProof {
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.pseudonym.serialize());
        serialized.extend_from_slice(&self.op.serialize());
        serialized.extend_from_slice(&self.ut.serialize());
        serialized
    }
}

impl Deserialize for PseudonymProof {
    fn deserialize(bytes: &[u8]) -> Self {
        let pseudonym = G1Affine::deserialize(&bytes[..LENGTH_G1_POINT]);
        let op = G1Affine::deserialize(&bytes[LENGTH_G1_POINT..LENGTH_G1_POINT * 2]);
        let ut = G1Affine::deserialize(&bytes[LENGTH_G1_POINT * 2..]);
        PseudonymProof { pseudonym, op, ut }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Proof {
    a_bar: G1Affine,
    b_bar: G1Affine,
    d: G1Affine,
    e_hat: Scalar,
    r_1_hat: Scalar,
    r_3_hat: Scalar,
    m_hats: Vec<Scalar>,
    challenge: Scalar,
}

impl Serialize for Proof {
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.a_bar.serialize());
        serialized.extend_from_slice(&self.b_bar.serialize());
        serialized.extend_from_slice(&self.d.serialize());
        serialized.extend_from_slice(&self.e_hat.serialize());
        serialized.extend_from_slice(&self.r_1_hat.serialize());
        serialized.extend_from_slice(&self.r_3_hat.serialize());
        for m_hat in &self.m_hats {
            serialized.extend_from_slice(&m_hat.serialize());
        }
        serialized.extend_from_slice(&self.challenge.serialize());
        serialized
    }
}

impl Deserialize for Proof {
    fn deserialize(bytes: &[u8]) -> Self {
        let a_bar = G1Affine::deserialize(&bytes[..LENGTH_G1_POINT]);
        let b_bar = G1Affine::deserialize(&bytes[LENGTH_G1_POINT..LENGTH_G1_POINT * 2]);
        let d = G1Affine::deserialize(&bytes[LENGTH_G1_POINT * 2..LENGTH_G1_POINT * 3]);
        let e_hat =
            Scalar::deserialize(&bytes[LENGTH_G1_POINT * 3..LENGTH_G1_POINT * 3 + LENGTH_SCALAR]);
        let r_1_hat = Scalar::deserialize(
            &bytes[LENGTH_G1_POINT * 3 + LENGTH_SCALAR..LENGTH_G1_POINT * 3 + LENGTH_SCALAR * 2],
        );
        let r_3_hat = Scalar::deserialize(
            &bytes
                [LENGTH_G1_POINT * 3 + LENGTH_SCALAR * 2..LENGTH_G1_POINT * 3 + LENGTH_SCALAR * 3],
        );

        let mut m_hats = Vec::new();
        let mut offset = LENGTH_G1_POINT * 3 + LENGTH_SCALAR * 3;
        while offset + LENGTH_SCALAR < bytes.len() {
            m_hats.push(Scalar::deserialize(&bytes[offset..offset + LENGTH_SCALAR]));
            offset += LENGTH_SCALAR;
        }

        let challenge = Scalar::deserialize(&bytes[offset..]);
        Proof {
            a_bar,
            b_bar,
            d,
            e_hat,
            r_1_hat,
            r_3_hat,
            m_hats,
            challenge,
        }
    }
}

impl Export for Proof {
    fn export(&self) -> JsValue {
        JsValue::from_str(&bytes_to_hex(&self.serialize()))
    }
}

impl Import for Proof {
    fn import(source: &JsValue) -> Self {
        Proof::deserialize(&hex_to_bytes(&source.as_string().unwrap()))
    }
}

pub(crate) fn export_proof_with_pseudonym(proof: &Proof, pseudonym: &G1Affine) -> JsValue {
    let mut serialized = Vec::new();
    serialized.extend_from_slice(&proof.serialize());
    serialized.extend_from_slice(&pseudonym.serialize());
    JsValue::from_str(&bytes_to_hex(&serialized))
}
