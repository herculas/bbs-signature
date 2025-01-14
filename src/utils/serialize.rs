use bls12_381::{G1Affine, G2Affine, Scalar};
use wasm_bindgen::JsValue;
use crate::suite::constants::{LENGTH_G1_POINT, LENGTH_G2_POINT, LENGTH_SCALAR};
use crate::utils::format::{bytes_to_hex, hex_to_bytes, i2osp, os2ip};

pub trait Serialize {
    fn serialize(&self) -> Vec<u8>;
}

pub trait Deserialize {
    fn deserialize(bytes: &[u8]) -> Self;
}

pub trait Export {
    fn export(&self) -> JsValue;
}

pub trait Import {
    fn import(source: &JsValue) -> Self;
}

impl Serialize for G1Affine {
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.to_compressed());
        serialized
    }
}

impl Serialize for G2Affine {
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.to_compressed());
        serialized
    }
}

impl Serialize for Scalar {
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.to_bytes());
        serialized.reverse();
        serialized
    }
}

impl Export for Scalar {
    fn export(&self) -> JsValue {
        JsValue::from_str(&bytes_to_hex(&self.to_bytes()))
    }
}

impl Serialize for u64 {
    fn serialize(&self) -> Vec<u8> {
        i2osp(*self, 8)
    }
}

impl Deserialize for G1Affine {
    fn deserialize(bytes: &[u8]) -> Self {
        let bytes_array: &[u8; LENGTH_G1_POINT] =
            bytes.try_into().expect("The provided bytes MUST be 48 bytes long!");
        G1Affine::from_compressed(bytes_array).unwrap()
    }
}

impl Deserialize for G2Affine {
    fn deserialize(bytes: &[u8]) -> Self {
        let bytes_array: &[u8; LENGTH_G2_POINT] =
            bytes.try_into().expect("The provided bytes MUST be 96 bytes long!");
        G2Affine::from_compressed(bytes_array).unwrap()
    }
}

impl Deserialize for Scalar {
    fn deserialize(bytes: &[u8]) -> Self {
        let mut bytes = bytes.to_vec();
        bytes.reverse();
        let bytes_array: &[u8; LENGTH_SCALAR] = bytes
            .as_slice()
            .try_into()
            .expect("The provided bytes MUST be 32 bytes long!");
        Scalar::from_bytes(&bytes_array).unwrap()
    }
}

impl Deserialize for u64 {
    fn deserialize(bytes: &[u8]) -> Self {
        os2ip(&bytes)
    }
}

impl Import for Scalar {
    fn import(source: &JsValue) -> Self {
        Scalar::deserialize(&hex_to_bytes(&source.as_string().unwrap()))
    }
}

impl Import for Vec<u8> {
    fn import(source: &JsValue) -> Self {
        let array: js_sys::Uint8Array = js_sys::Uint8Array::new(&source);
        let mut bytes = vec![0; array.length() as usize];
        array.copy_to(&mut bytes);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::format::bytes_to_hex;

    #[test]
    fn test_serialize_g1_point() {
        let point = G1Affine::generator();
        let serialized = point.serialize();
        let deserialized = G1Affine::deserialize(&serialized);

        assert_eq!(
            bytes_to_hex(&serialized),
            "\
                97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905\
                a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        );
        assert_eq!(point, deserialized);
    }

    #[test]
    fn test_serialize_g2_point() {
        let point = G2Affine::generator();
        let serialized = point.serialize();
        let deserialized = G2Affine::deserialize(&serialized);

        assert_eq!(
            bytes_to_hex(&serialized),
            "\
                93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049\
                334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051\
                c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        );
        assert_eq!(point, deserialized);
    }

    #[test]
    fn test_serialize_scalar() {
        let scalar = Scalar::from(11451419198101141145) * Scalar::from(14191981011451419198);
        let serialized = scalar.serialize();
        let deserialized = Scalar::deserialize(&serialized);

        assert_eq!(
            bytes_to_hex(&serialized),
            "000000000000000000000000000000007a43e4009e2ad8d17877b5d6764b430e"
        );
        assert_eq!(scalar, deserialized);
    }

    #[test]
    fn test_serialize_number() {
        let num = 1145141919810114;
        let serialized = num.serialize();
        let deserialized = u64::deserialize(&serialized);

        assert_eq!(bytes_to_hex(&serialized), "0004118021590242");
        assert_eq!(num, deserialized);
    }
}