use crate::proof::{export_proof_with_pseudonym, Proof};
use crate::signature::{export_blindness, export_signature_with_entropy, Signature};
use crate::utils::serialize::{
    import_cipher, import_option_bytes, import_option_g1_affine, import_option_scalar,
    import_option_usize, import_option_vec_bytes, Export, Import,
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
    material: &JsValue,
    info: &JsValue,
    dst: &JsValue,
    cipher: &JsValue,
) -> JsValue {
    let material = Vec::import(&material);
    let info = import_option_bytes(&info);
    let dst = import_option_bytes(&dst);
    let cipher = import_cipher(&cipher);

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
        None,
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

    JsValue::from_bool(proof::interface::validate(
        &public_key,
        &proof,
        header.as_deref(),
        presentation_header.as_deref(),
        disclosed_messages.as_ref(),
        disclosed_indexes.as_ref(),
        &cipher,
    ))
}

#[wasm_bindgen]
pub fn blind_messages(committed_messages: JsValue, cipher: JsValue) -> JsValue {
    let committed_messages = import_option_vec_bytes(&committed_messages);
    let cipher = import_cipher(&cipher);

    let committed_messages: Option<Vec<&[u8]>> = committed_messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());

    let (commitment_with_proof, prover_blind) =
        signature::interface::blind_messages(committed_messages.as_ref(), None, &cipher, None);
    export_blindness(&commitment_with_proof, &prover_blind)
}

#[wasm_bindgen]
pub fn blind_sign(
    secret_key: JsValue,
    public_key: JsValue,
    commitment_with_proof: JsValue,
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

    let commitment_with_proof = import_option_bytes(&commitment_with_proof);

    signature::interface::blind_sign(
        &secret_key,
        &public_key,
        commitment_with_proof.as_deref(),
        header.as_deref(),
        messages.as_ref(),
        &cipher,
    )
    .export()
}

#[wasm_bindgen]
pub fn blind_verify(
    public_key: JsValue,
    signature: JsValue,
    header: JsValue,
    messages: JsValue,
    committed_messages: JsValue,
    prover_blind: JsValue,
    cipher: JsValue,
) -> JsValue {
    let public_key: Vec<u8> = Vec::import(&public_key);
    let signature: Signature = Signature::import(&signature);
    let header = import_option_bytes(&header);
    let cipher = import_cipher(&cipher);

    let messages = import_option_vec_bytes(&messages);
    let committed_messages = import_option_vec_bytes(&committed_messages);

    let messages: Option<Vec<&[u8]>> = messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());
    let committed_messages: Option<Vec<&[u8]>> = committed_messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());
    let prover_blind = import_option_scalar(&prover_blind);

    JsValue::from_bool(signature::interface::blind_verify(
        &public_key,
        &signature,
        header.as_deref(),
        messages.as_ref(),
        committed_messages.as_ref(),
        prover_blind.as_ref(),
        &cipher,
    ))
}

#[wasm_bindgen]
pub fn blind_prove(
    public_key: JsValue,
    signature: JsValue,
    header: JsValue,
    presentation_header: JsValue,
    messages: JsValue,
    committed_messages: JsValue,
    disclosed_indexes: JsValue,
    disclosed_commitment_indexes: JsValue,
    prover_blind: JsValue,
    cipher: JsValue,
) -> JsValue {
    let public_key: Vec<u8> = Vec::import(&public_key);
    let signature: Signature = Signature::import(&signature);
    let header = import_option_bytes(&header);
    let presentation_header = import_option_bytes(&presentation_header);
    let cipher = import_cipher(&cipher);

    let messages = import_option_vec_bytes(&messages);
    let committed_messages = import_option_vec_bytes(&committed_messages);

    let messages: Option<Vec<&[u8]>> = messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());
    let committed_messages: Option<Vec<&[u8]>> = committed_messages
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
    let disclosed_commitment_indexes: Option<Vec<usize>> =
        if !disclosed_commitment_indexes.is_undefined() {
            Some(
                Vec::<usize>::import(&disclosed_commitment_indexes)
                    .iter()
                    .map(|idx| *idx)
                    .collect(),
            )
        } else {
            None
        };

    let prover_blind = import_option_scalar(&prover_blind);

    proof::interface::blind_prove(
        &public_key,
        &signature,
        header.as_deref(),
        presentation_header.as_deref(),
        messages.as_ref(),
        committed_messages.as_ref(),
        disclosed_indexes.as_ref(),
        disclosed_commitment_indexes.as_ref(),
        prover_blind.as_ref(),
        &cipher,
        None,
    )
    .export()
}

#[wasm_bindgen]
pub fn blind_validate(
    public_key: JsValue,
    proof: JsValue,
    header: JsValue,
    presentation_header: JsValue,
    l: JsValue,
    disclosed_messages: JsValue,
    disclosed_commitment_messages: JsValue,
    disclosed_indexes: JsValue,
    disclosed_commitment_indexes: JsValue,
    cipher: JsValue,
) -> JsValue {
    let public_key: Vec<u8> = Vec::import(&public_key);
    let proof = Proof::import(&proof);
    let header = import_option_bytes(&header);
    let presentation_header = import_option_bytes(&presentation_header);
    let cipher = import_cipher(&cipher);

    let l = import_option_usize(&l);

    let disclosed_messages = import_option_vec_bytes(&disclosed_messages);
    let disclosed_commitment_messages = import_option_vec_bytes(&disclosed_commitment_messages);

    let disclosed_messages: Option<Vec<&[u8]>> = disclosed_messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());
    let disclosed_commitment_messages: Option<Vec<&[u8]>> = disclosed_commitment_messages
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
    let disclosed_commitment_indexes: Option<Vec<usize>> =
        if !disclosed_commitment_indexes.is_undefined() {
            Some(
                Vec::<usize>::import(&disclosed_commitment_indexes)
                    .iter()
                    .map(|idx| *idx)
                    .collect(),
            )
        } else {
            None
        };

    JsValue::from_bool(proof::interface::blind_validate(
        &public_key,
        &proof,
        header.as_deref(),
        presentation_header.as_deref(),
        l,
        disclosed_messages.as_ref(),
        disclosed_commitment_messages.as_ref(),
        disclosed_indexes.as_ref(),
        disclosed_commitment_indexes.as_ref(),
        &cipher,
    ))
}

#[wasm_bindgen]
pub fn blind_messages_with_nym(
    committed_messages: JsValue,
    prover_nym: JsValue,
    cipher: JsValue,
) -> JsValue {
    let committed_messages = import_option_vec_bytes(&committed_messages);
    let prover_nym = import_option_scalar(&prover_nym);
    let cipher = import_cipher(&cipher);

    let committed_messages: Option<Vec<&[u8]>> = committed_messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());

    let (commitment_with_proof, prover_blind) = signature::interface::blind_messages_with_nym(
        committed_messages.as_ref(),
        prover_nym.as_ref(),
        None,
        &cipher,
        None,
    );
    export_blindness(&commitment_with_proof, &prover_blind)
}

#[wasm_bindgen]
pub fn blind_sign_with_nym(
    secret_key: JsValue,
    public_key: JsValue,
    commitment_with_proof: JsValue,
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

    let commitment_with_proof = import_option_bytes(&commitment_with_proof);

    let (signature, entropy) = signature::interface::blind_sign_with_nym(
        &secret_key,
        &public_key,
        commitment_with_proof.as_deref(),
        header.as_deref(),
        messages.as_ref(),
        &cipher,
    );
    export_signature_with_entropy(&signature, &entropy)
}

#[wasm_bindgen]
pub fn blind_verify_with_nym(
    public_key: JsValue,
    signature: JsValue,
    header: JsValue,
    messages: JsValue,
    committed_messages: JsValue,
    prover_nym: JsValue,
    signer_nym_entropy: JsValue,
    prover_blind: JsValue,
    cipher: JsValue,
) -> JsValue {
    let public_key: Vec<u8> = Vec::import(&public_key);
    let signature: Signature = Signature::import(&signature);
    let header = import_option_bytes(&header);
    let cipher = import_cipher(&cipher);
    let prover_nym = import_option_scalar(&prover_nym);
    let signer_nym_entropy = import_option_scalar(&signer_nym_entropy);
    let prover_blind = import_option_scalar(&prover_blind);

    let messages = import_option_vec_bytes(&messages);
    let committed_messages = import_option_vec_bytes(&committed_messages);

    let messages: Option<Vec<&[u8]>> = messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());
    let committed_messages: Option<Vec<&[u8]>> = committed_messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());

    let res = signature::interface::blind_verify_with_nym(
        &public_key,
        &signature,
        header.as_deref(),
        messages.as_ref(),
        committed_messages.as_ref(),
        prover_nym.as_ref(),
        signer_nym_entropy.as_ref(),
        prover_blind.as_ref(),
        &cipher,
    );

    if res.is_some() {
        res.unwrap().export()
    } else {
        JsValue::from_str("false")
    }
}

#[wasm_bindgen]
pub fn blind_prove_with_nym(
    public_key: JsValue,
    signature: JsValue,
    header: JsValue,
    presentation_header: JsValue,
    nym_secret: JsValue,
    context_id: JsValue,
    messages: JsValue,
    committed_messages: JsValue,
    disclosed_indexes: JsValue,
    disclosed_commitment_indexes: JsValue,
    prover_blind: JsValue,
    cipher: JsValue,
) -> JsValue {
    let public_key: Vec<u8> = Vec::import(&public_key);
    let signature: Signature = Signature::import(&signature);
    let header = import_option_bytes(&header);
    let presentation_header = import_option_bytes(&presentation_header);
    let nym_secret = import_option_scalar(&nym_secret);
    let context_id = import_option_bytes(&context_id);
    let cipher = import_cipher(&cipher);
    let prover_blind = import_option_scalar(&prover_blind);

    let messages = import_option_vec_bytes(&messages);
    let committed_messages = import_option_vec_bytes(&committed_messages);

    let messages: Option<Vec<&[u8]>> = messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());
    let committed_messages: Option<Vec<&[u8]>> = committed_messages
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
    let disclosed_commitment_indexes: Option<Vec<usize>> =
        if !disclosed_commitment_indexes.is_undefined() {
            Some(
                Vec::<usize>::import(&disclosed_commitment_indexes)
                    .iter()
                    .map(|idx| *idx)
                    .collect(),
            )
        } else {
            None
        };

    let (proof, pseudonym) = proof::interface::blind_prove_with_nym(
        &public_key,
        &signature,
        header.as_deref(),
        presentation_header.as_deref(),
        nym_secret.as_ref(),
        context_id.as_deref(),
        messages.as_ref(),
        committed_messages.as_ref(),
        disclosed_indexes.as_ref(),
        disclosed_commitment_indexes.as_ref(),
        prover_blind.as_ref(),
        &cipher,
        None,
    );
    export_proof_with_pseudonym(&proof, &pseudonym)
}

#[wasm_bindgen]
pub fn blind_validate_with_nym(
    public_key: JsValue,
    proof: JsValue,
    header: JsValue,
    presentation_header: JsValue,
    pseudonym: JsValue,
    context_id: JsValue,
    l: JsValue,
    disclosed_messages: JsValue,
    disclosed_commitment_messages: JsValue,
    disclosed_indexes: JsValue,
    disclosed_commitment_indexes: JsValue,
    cipher: JsValue,
) -> JsValue {
    let public_key: Vec<u8> = Vec::import(&public_key);
    let proof = Proof::import(&proof);
    let header = import_option_bytes(&header);
    let presentation_header = import_option_bytes(&presentation_header);
    let pseudonym = import_option_g1_affine(&pseudonym);
    let context_id = import_option_bytes(&context_id);
    let cipher = import_cipher(&cipher);
    let l = import_option_usize(&l);

    let disclosed_messages = import_option_vec_bytes(&disclosed_messages);
    let disclosed_commitment_messages = import_option_vec_bytes(&disclosed_commitment_messages);

    let disclosed_messages: Option<Vec<&[u8]>> = disclosed_messages
        .as_ref()
        .map(|vec| vec.iter().map(|msg| msg.as_slice()).collect());
    let disclosed_commitment_messages: Option<Vec<&[u8]>> = disclosed_commitment_messages
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
    let disclosed_commitment_indexes: Option<Vec<usize>> =
        if !disclosed_commitment_indexes.is_undefined() {
            Some(
                Vec::<usize>::import(&disclosed_commitment_indexes)
                    .iter()
                    .map(|idx| *idx)
                    .collect(),
            )
        } else {
            None
        };

    JsValue::from_bool(proof::interface::blind_validate_with_nym(
        &public_key,
        &proof,
        header.as_deref(),
        presentation_header.as_deref(),
        pseudonym.as_ref(),
        context_id.as_deref(),
        l,
        disclosed_messages.as_ref(),
        disclosed_commitment_messages.as_ref(),
        disclosed_indexes.as_ref(),
        disclosed_commitment_indexes.as_ref(),
        &cipher,
    ))
}
