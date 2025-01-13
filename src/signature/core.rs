use crate::signature::Signature;
use crate::suite::cipher::Cipher;
use crate::utils::scalar::{calculate_domain, hash_to_scalar};
use crate::utils::serialize::{Deserialize, Serialize};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Prepared, Gt, Scalar};

/// Compute a deterministic signature from a secret key, a set of messages, and optionally a header
/// and a vector of messages.
///
/// - `secret_key`: a scalar representing the secret key.
/// - `public_key`: an octet string representing the public key.
/// - `generators`: a list of pseudo-random G1 generators.
/// - `header`: an octet string containing the context and application specific information.
/// - `messages`: a list of scalars representing the messages.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return a signature.
pub(super) fn sign(
    secret_key: &Scalar,
    public_key: &[u8],
    generators: &Vec<G1Affine>,
    header: Option<&[u8]>,
    messages: Option<&Vec<Scalar>>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> Signature {
    let empty_vec = vec![];
    let inner_messages = messages.unwrap_or(&empty_vec);
    let inner_header = header.unwrap_or(&[]);
    let inner_api_id = api_id.unwrap_or(&[]);

    // Definitions:
    //
    // - hash_to_scalar_dst: an octet string representing the domain separation tag:
    //                       "<api_id> || H2S_".
    let hash_to_scalar_dst = [inner_api_id, b"H2S_"].concat();

    // Deserialization:
    //
    // 1. L := len(messages).
    // 2. If len(generators) != L + 1, return INVALID.
    // 3. (msg_1, msg_2, ..., msg_L) := messages.
    // 4. (Q_1, H_1, ..., H_L) := generators.
    let l = inner_messages.len();
    if generators.len() != l + 1 {
        panic!("the number of generators must be equal to the number of messages plus one");
    }
    let q_1 = generators[0];
    let h_points = &generators[1..];

    // Procedure:
    //
    // 1. domain := calculate_domain(public_key, Q_1, (H_1, ..., H_L), header, api_id).
    // 2. e := hash_to_scalar(serialize(secret_key, msg_1, ..., msg_L, domain), hash_to_scalar_dst).
    // 3. B := P_1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L.
    // 4. A := B * (1 / (secret_key + e)).
    // 5. Return (A, e).
    let domain = calculate_domain(
        &public_key,
        q_1,
        h_points.to_vec(),
        Some(&inner_header),
        Some(&inner_api_id),
        &cipher,
    );
    let secret_key_serialized = secret_key.serialize();
    let message_serialized: Vec<u8> = inner_messages
        .iter()
        .flat_map(|message| message.serialize())
        .collect();
    let domain_serialized = domain.serialize();
    let e = hash_to_scalar(
        &[
            secret_key_serialized.as_slice(),
            message_serialized.as_slice(),
            domain_serialized.as_slice(),
        ]
            .concat(),
        &hash_to_scalar_dst,
        &cipher,
    );
    let p_1: G1Affine = G1Affine::from_compressed(&cipher.singularity).unwrap();
    let b: G1Projective = h_points.iter().zip(inner_messages.iter()).fold(
        (p_1 + q_1 * domain).into(),
        |acc: G1Projective, (h, msg)| (acc + h * msg).into(),
    );
    let a: G1Affine = (b * (secret_key + e).invert().unwrap()).into();
    Signature { a, e }
}

/// Check if a given signature is valid for a given set of generators, header, and vector of
/// messages, against a given public key. The set of messages MUST be supplied in the same order
/// as they were signed.
///
/// - `public_key`: an octet string representing the public key.
/// - `signature`: a signature.
/// - `generators`: a list of pseudo-random G1 generators.
/// - `header`: an octet string containing the context and application specific information.
/// - `messages`: a list of scalars representing the messages.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return `true` if the signature is valid, `false` otherwise.
pub(super) fn verify(
    public_key: &[u8],
    signature: &Signature,
    generators: &Vec<G1Affine>,
    header: Option<&[u8]>,
    messages: Option<&Vec<Scalar>>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> bool {
    let empty_vec = vec![];
    let inner_messages = messages.unwrap_or(&empty_vec);
    let inner_header = header.unwrap_or(&[]);
    let inner_api_id = api_id.unwrap_or(&[]);

    // Deserialization:
    //
    // 1. signature_result := octets_to_signature(signature).
    // 2. If signature_result is INVALID, return INVALID.
    // 3. (A, e) := signature_result.
    // 4. W := octet_to_public_key(public_key).
    // 5. If W is INVALID, return INVALID.
    // 6. L := len(messages).
    // 7. If len(generators) != L + 1, return INVALID.
    // 8. (msg_1, msg_2, ..., msg_L) := messages.
    // 9. (Q_1, H_1, ..., H_L) := generators.
    let a = signature.a;
    let e = signature.e;
    let w = G2Affine::deserialize(&public_key);
    let l = inner_messages.len();
    if generators.len() != l + 1 {
        panic!("the number of generators must be equal to the number of messages plus one");
    }
    let q_1 = generators[0];
    let h_points = &generators[1..];

    // Procedure:
    //
    // 1. domain := calculate_domain(public_key, Q_1, (H_1, ..., H_L), header, api_id).
    // 2. B := P_1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L.
    // 3. If h(A, W + BP2 * e) * h(B, -BP2) != Identity_GT, return INVALID.
    // 4. Return VALID.
    let domain = calculate_domain(
        &public_key,
        q_1,
        h_points.to_vec(),
        Some(&inner_header),
        Some(&inner_api_id),
        &cipher,
    );
    let p_1: G1Affine = G1Affine::from_compressed(&cipher.singularity).unwrap();
    let b: G1Projective = h_points.iter().zip(inner_messages.iter()).fold(
        (p_1 + q_1 * domain).into(),
        |acc: G1Projective, (h, msg)| (acc + h * msg).into(),
    );

    (cipher.pairing_compare)(
        &[
            (
                &a,
                &G2Prepared::from(G2Affine::from(&(w + G2Affine::generator() * e))),
            ),
            (
                &G1Affine::from(b),
                &G2Prepared::from(-G2Affine::generator()),
            ),
        ],
        &Gt::identity(),
    )
}
