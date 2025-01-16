use crate::proof::Proof;
use crate::signature::Signature;
use crate::utils::serialize::{
    import_cipher, import_option_bytes, import_option_vec_bytes, Export, Import,
};
use bls12_381::Scalar;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

mod keypair;
mod proof;
mod signature;
mod suite;
mod utils;

#[wasm_bindgen]
pub fn generate_secret_key(
    raw_material: &JsValue,
    raw_info: &JsValue,
    raw_dst: &JsValue,
    raw_cipher: &JsValue,
) -> JsValue {
    let material = Vec::import(&raw_material);
    let info = import_option_bytes(&raw_info);
    let dst = import_option_bytes(&raw_dst);
    let cipher = import_cipher(&raw_cipher);
    keypair::generate_secret_key(&material, info.as_deref(), dst.as_deref(), &cipher).export()
}

#[wasm_bindgen]
pub fn derive_public_key(raw_secret_key: &JsValue) -> JsValue {
    let secret_key = Scalar::import(&raw_secret_key);
    let public_key = keypair::derive_public_key(&secret_key);
    public_key.to_vec().export()
}

#[wasm_bindgen]
pub fn sign(
    secret_key: JsValue,
    public_key: JsValue,
    header: JsValue,
    messages: JsValue,
    cipher: JsValue,
) -> JsValue {
    let secret_key: Scalar = Scalar::import(&secret_key);
    let public_key: Vec<u8> = Vec::import(&public_key);
    let header = import_option_bytes(&header);
    let messages = import_option_vec_bytes(&messages);
    let cipher = import_cipher(&cipher);

    let messages: Option<Vec<&[u8]>> = messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());

    signature::interface::sign(
        &secret_key,
        &public_key,
        header.as_deref(),
        messages.as_ref(),
        &cipher,
    )
    .export()
}

#[wasm_bindgen]
pub fn verify(
    public_key: JsValue,
    signature: JsValue,
    header: JsValue,
    messages: JsValue,
    cipher: JsValue,
) -> JsValue {
    let public_key: Vec<u8> = Vec::import(&public_key);
    let signature: Signature = Signature::import(&signature);
    let header = import_option_bytes(&header);
    let messages = import_option_vec_bytes(&messages);
    let cipher = import_cipher(&cipher);

    let messages: Option<Vec<&[u8]>> = messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());

    JsValue::from_bool(signature::interface::verify(
        &public_key,
        &signature,
        header.as_deref(),
        messages.as_ref(),
        &cipher,
    ))
}

#[wasm_bindgen]
pub fn prove(
    public_key: JsValue,
    signature: JsValue,
    header: JsValue,
    presentation_header: JsValue,
    messages: JsValue,
    disclosed_indexes: JsValue,
    cipher: JsValue,
) -> JsValue {
    let public_key: Vec<u8> = Vec::import(&public_key);
    let signature: Signature = Signature::import(&signature);
    let header = import_option_bytes(&header);
    let presentation_header = import_option_bytes(&presentation_header);
    let messages = import_option_vec_bytes(&messages);
    let cipher = import_cipher(&cipher);

    let messages: Option<Vec<&[u8]>> = messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());

    let disclosed_indexes: Option<Vec<usize>> = if !disclosed_indexes.is_undefined() {
        Some(
            Vec::<usize>::import(&disclosed_indexes)
                .iter()
                .map(|idx| *idx)
                .collect(),
        )
    } else {
        None
    };

    proof::interface::prove(
        &public_key,
        &signature,
        header.as_deref(),
        presentation_header.as_deref(),
        messages.as_ref(),
        disclosed_indexes.as_ref(),
        &cipher,
    )
    .export()
}

#[wasm_bindgen]
pub fn validate(
    public_key: JsValue,
    proof: JsValue,
    header: JsValue,
    presentation_header: JsValue,
    disclosed_messages: JsValue,
    disclosed_indexes: JsValue,
    cipher: JsValue,
) -> JsValue {
    let public_key: Vec<u8> = Vec::import(&public_key);
    let proof = Proof::import(&proof);
    let header = import_option_bytes(&header);
    let presentation_header = import_option_bytes(&presentation_header);
    let disclosed_messages = import_option_vec_bytes(&disclosed_messages);
    let cipher = import_cipher(&cipher);

    let disclosed_messages: Option<Vec<&[u8]>> = disclosed_messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());

    let disclosed_indexes: Option<Vec<usize>> = if !disclosed_indexes.is_undefined() {
        Some(
            Vec::<usize>::import(&disclosed_indexes)
                .iter()
                .map(|idx| *idx)
                .collect(),
        )
    } else {
        None
    };

    JsValue::from_bool(proof::interface::verify(
        &public_key,
        &proof,
        header.as_deref(),
        presentation_header.as_deref(),
        disclosed_messages.as_ref(),
        disclosed_indexes.as_ref(),
        &cipher,
    ))
}
