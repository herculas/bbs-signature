use crate::suite::instance::{BLS12_381_G1_XMD_SHA_256, BLS12_381_G1_XOF_SHAKE_256};
use crate::utils::serialize::{Export, Import};
use bls12_381::Scalar;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

mod keypair;
mod proof;
mod signature;
mod suite;
mod utils;

#[wasm_bindgen(js_name = generateSecretKey)]
pub fn generate_secret_key(
    raw_material: &JsValue,
    raw_info: &JsValue,
    raw_dst: &JsValue,
    raw_cipher: &JsValue,
) -> JsValue {
    let material = Vec::import(&raw_material);
    let info: Option<Vec<u8>> = match raw_info.is_undefined() || raw_info.is_null() {
        true => None,
        false => Some(Vec::import(&raw_info)),
    };
    let info = info.as_deref();
    let dst: Option<Vec<u8>> = match raw_dst.is_undefined() || raw_dst.is_null() {
        true => None,
        false => Some(Vec::import(&raw_dst)),
    };
    let dst = dst.as_deref();
    let cipher = match raw_cipher.as_string().unwrap().as_str() {
        "BLS12_381_G1_XMD_SHA_256" => BLS12_381_G1_XMD_SHA_256,
        "BLS12_381_G1_XOF_SHAKE_256" => BLS12_381_G1_XOF_SHAKE_256,
        _ => panic!("Invalid cipher"),
    };
    keypair::generate_secret_key(&material, info, dst, &cipher).export()
}

#[wasm_bindgen]
pub fn sign(
    raw_secret_key: JsValue,
    raw_public_key: JsValue,
    raw_header: JsValue,
    raw_messages: JsValue,
    raw_cipher: JsValue,
) {
    let secret_key: Scalar = Scalar::import(&raw_secret_key);
    let public_key: Vec<u8> = Vec::import(&raw_public_key);

    // let public_key = keypair::PublicKey::from(raw_public_key);
    // let header = proof::Header::from(raw_header);
    // let messages = proof::Messages::from(raw_messages);
    // let cipher = proof::Cipher::from(raw_cipher);
    //
    // let suite = suite::Suite::new(secret_key, public_key, header, messages, cipher);
    // let signature = suite.sign();
    // signature.to_js_value();
}
