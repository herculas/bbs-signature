use crate::proof::subroutine::{
    calculate_challenge, finalize_proof, initialize_proof, prepare_verification,
};
use crate::proof::Proof;
use crate::signature::Signature;
use crate::suite::cipher::Cipher;
use crate::utils::scalar::random_scalar;
use crate::utils::serialize::Deserialize;
use bls12_381::{G1Affine, G2Affine, G2Prepared, Gt, Scalar};

/// Compute a zero-knowledge proof-of-knowledge of a signature, while optionally selectively disclosing from the origin
/// set of signed messages. The prover may also supply a presentation header.
///
/// The message supplied in this operation MUST be in the same order as they were signed. To specify which of those
/// messages will be disclosed, the prover can supply the list of indexes that the disclosed messages have in the array
/// of the signed messages.
///
/// - `public_key`: an octet string representing the public key.
/// - `signature`: a signature.
/// - `generators`: a list of pseudo-random G1 generators.
/// - `header`: an octet string containing the context and application specific information.
/// - `presentation_header`: an octet string containing the context specific information.
/// - `messages`: a list of scalars representing the messages.
/// - `disclosed_indexes`: a list of indexes of the disclosed messages.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return a proof.
pub(super) fn prove(
    public_key: &[u8],
    signature: &Signature,
    generators: &Vec<G1Affine>,
    header: Option<&[u8]>,
    presentation_header: Option<&[u8]>,
    messages: Option<&Vec<Scalar>>,
    disclosed_indexes: Option<&Vec<usize>>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> Proof {
    let empty_message_vec = vec![];
    let empty_index_vec = vec![];
    let inner_messages = messages.unwrap_or(&empty_message_vec);
    let inner_disclosed_indexes = disclosed_indexes.unwrap_or(&empty_index_vec);

    // Deserialization:
    //
    // 1. signature_result := octets_to_signature(signature).
    // 2. If signature_result is INVALID, return INVALID.
    // 3. (A, e) := signature_result.
    //
    // 4. L := len(messages).
    // 5. R := len(disclosed_indexes).
    // 6. If R > L, return INVALID.
    // 7. U := L - R.
    // 8. For i in disclosed_indexes: if i < 0 or i > L - 1, return INVALID.
    // 9. undisclosed_indexes := (0, 1, ..., L - 1) \ disclosed_indexes.
    // 10. (i_1, i_2, ..., i_R) := disclosed_indexes.
    // 11. (j_1, j_2, ..., j_U) := undisclosed_indexes.
    //
    // 12. disclosed_messages := (messages[i_1], messages[i_2], ..., messages[i_R]).
    // 13. undisclosed_messages := (messages[j_1], messages[j_2], ..., messages[j_U]).
    let e = signature.e;
    let l = inner_messages.len();
    let r = inner_disclosed_indexes.len();
    if r > l {
        panic!("Invalid disclosed indexes");
    }
    let u = l - r;
    inner_disclosed_indexes.iter().for_each(|&i| {
        if i > l - 1 {
            panic!("Invalid disclosed indexes");
        }
    });

    let undisclosed_indexes = (0..l)
        .filter(|i| !inner_disclosed_indexes.contains(i))
        .collect::<Vec<usize>>();
    let disclosed_messages = inner_disclosed_indexes
        .iter()
        .map(|&i| inner_messages[i])
        .collect::<Vec<Scalar>>();
    let undisclosed_messages = undisclosed_indexes
        .iter()
        .map(|&i| inner_messages[i])
        .collect::<Vec<Scalar>>();

    // Procedure:
    //
    // 1. random_scalars := calculate_random_scalars(U + 5).
    // 2. init_res := proof_init(
    //          public_key,
    //          signature_result,
    //          generators,
    //          random_scalars,
    //          header,
    //          messages,
    //          undisclosed_indexes,
    //          api_id).
    // 3. If init_res is INVALID, return INVALID.
    // 4. challenge := proof_challenge_calculate(
    //          init_res,
    //          disclosed_indexes,
    //          disclosed_messages,
    //          presentation_header).
    // 5. If challenge is INVALID, return INVALID.
    // 6. proof := proof_finalize(init_res, challenge, e, random_scalars, undisclosed_messages).

    let random_scalars = random_scalar(u + 5);
    let init_res = initialize_proof(
        public_key,
        signature,
        generators,
        &random_scalars,
        header,
        messages,
        Some(&undisclosed_indexes),
        api_id,
        cipher,
    );
    let c = calculate_challenge(
        &init_res,
        Some(&disclosed_messages),
        disclosed_indexes,
        presentation_header,
        api_id,
        cipher,
    );
    finalize_proof(
        &init_res,
        &c,
        &e,
        &random_scalars,
        Some(&undisclosed_messages),
    )
}

/// Check if a proof is valid for a header, vector of disclosed messages, along with their index corresponding to their
/// original position when signed, and a presentation header, against a public key. Validating this proof guarantees the
/// authenticity and integrity of the header and the disclosed messages, as well as the knowledge of a valid BBS
/// Signature.
///
/// The inputted disclosed messages MUST be supplied to this operation in the same order as they were signed. Similarly,
/// the indexes of the disclosed messages MUST be supplied in the same order as the disclosed indexes during proof
/// generation.
///
/// - `public_key`: an octet string representing the public key.
/// - `proof`: a proof.
/// - `generators`: a list of pseudo-random G1 generators.
/// - `header`: an octet string containing the context and application specific information.
/// - `presentation_header`: an octet string containing the context specific information.
/// - `disclosed_messages`: a list of scalars representing the disclosed messages.
/// - `disclosed_indexes`: a list of indexes of the disclosed messages.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return `true` if the proof is valid, `false` otherwise.
pub(super) fn verify(
    public_key: &[u8],
    proof: &Proof,
    generators: &Vec<G1Affine>,
    header: Option<&[u8]>,
    presentation_header: Option<&[u8]>,
    disclosed_messages: Option<&Vec<Scalar>>,
    disclosed_indexes: Option<&Vec<usize>>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> bool {
    // Deserialization:
    //
    // 1. proof_result := octets_to_proof(proof).
    // 2. If proof_result is INVALID, return INVALID.
    // 3. (A_bar, B_bar, D, hat_e, hat_r_1, hat_r_3, commitments, cp) := proof_result.
    // 4. W := octet_to_public_key(public_key).
    let a_bar = proof.a_bar;
    let b_bar = proof.b_bar;
    let cp = proof.challenge;
    let w = G2Affine::deserialize(&public_key);

    // Procedure:
    //
    // 1. init_res := proof_verify_init(
    //          public_key,
    //          proof_result,
    //          generators,
    //          header,
    //          messages,
    //          disclosed_indexes,
    //          api_id).
    // 2. If init_res is INVALID, return INVALID.
    // 3. challenge := proof_challenge_calculate(
    //          init_res,
    //          disclosed_indexes,
    //          disclosed_messages,
    //          presentation_header).
    // 4. If challenge is INVALID, return INVALID.
    // 5. If cp != challenge, return INVALID.
    // 6. If h(A_bar, W) * h(B_bar, g_2) != Identity_GT, return INVALID.
    // 7. Return VALID.
    let init_res = prepare_verification(
        public_key,
        proof,
        generators,
        header,
        disclosed_messages,
        disclosed_indexes,
        api_id,
        cipher,
    );
    let c = calculate_challenge(
        &init_res,
        disclosed_messages,
        disclosed_indexes,
        presentation_header,
        api_id,
        cipher,
    );
    if cp != c {
        return false;
    }

    (cipher.pairing_compare)(
        &[
            (&a_bar, &G2Prepared::from(w)),
            (&b_bar, &G2Prepared::from(-G2Affine::generator())),
        ],
        &Gt::identity(),
    )
}
