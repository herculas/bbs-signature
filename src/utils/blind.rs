use crate::suite::cipher::Cipher;
use crate::suite::constants::{PADDING_BLIND, PADDING_HASH_TO_SCALAR};

use super::generator::create_generators;
use super::scalar::{hash_to_scalar, messages_to_scalars};
use super::serialize::Serialize;

use bls12_381::{G1Affine, G1Projective, Scalar};

/// Prepare the parameters for the proof of knowledge of a signature.
///
/// - `messages`: a list of octet strings. If not supplied, it defaults to an empty list.
/// - `committed_messages`: a list of octet strings. If not supplied, it defaults to an empty list.
/// - `generator_number`: the number of generators to create.
/// - `blind_generator_number`: the number of blind generators to create.
/// - `secret_prover_blind`: a scalar value. If not supplied, it defaults to the zero scalar.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: the cipher suite.
///
/// Return a vector `message_scalars` of scalar values, and a generator vector of points from the G1 group.
pub fn prepare_parameters(
    messages: Option<&Vec<&[u8]>>,
    committed_messages: Option<&Vec<&[u8]>>,
    generator_number: usize,
    blind_generator_number: usize,
    secret_prover_blind: Option<&Scalar>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> (Vec<Scalar>, Vec<G1Affine>) {
    let default_messages = vec![];
    let default_committed_messages = vec![];

    let messages = messages.unwrap_or(&default_messages);
    let committed_messages = committed_messages.unwrap_or(&default_committed_messages);

    // Procedure:
    //
    // 1. message_scalars := messages_to_scalars(messages, api_id).
    // 2. committed_message_scalars := [].
    // 3. If secret_prover_blind != None, committed_message_scalars.append(secret_prover_blind).
    // 4. committed_message_scalars.append(messages_to_scalars(committed_messages, api_id)).
    // 5. generators := create_generators(generators_number, api_id).
    // 6. blind_generators := create_generators(blind_generator_number, "BLIND_" || api_id).
    // 7. Return (message_scalars.append(committed_message_scalars), generators.append(blind_generators)).

    let mut message_scalars = messages_to_scalars(messages, api_id, cipher);

    let mut committed_message_scalars = Vec::new();
    if let Some(secret_prover_blind) = secret_prover_blind {
        committed_message_scalars.push(secret_prover_blind.clone());
    }

    committed_message_scalars.extend(messages_to_scalars(committed_messages, api_id, cipher));

    let mut generators = create_generators(generator_number, api_id, cipher);
    let blind_generator_dst = [PADDING_BLIND, api_id.unwrap_or(&[])].concat();
    let blind_generators =
        create_generators(blind_generator_number, Some(&blind_generator_dst), cipher);

    // message_scalars.extend(&committed_message_scalars);
    message_scalars.extend(committed_message_scalars);
    generators.extend(blind_generators);

    (message_scalars, generators)
}

/// Calculate the `b` value for the proof of knowledge of a signature.
///
/// - `generators`: a list of at least one point from the G1 group.
/// - `commitment`: a point from the G1 group. If not supplied, it defaults to the Identity_G1 point.
/// - `messages`: a list of scalar values. If not supplied, it defaults to an empty list.
/// - `cipher`: the cipher suite.
///
/// Return an element from the G1 subgroup, or INVALID.
pub fn calculate_b(
    generators: &Vec<G1Affine>,
    commitment: Option<&G1Affine>,
    messages: Option<&Vec<Scalar>>,
    cipher: &Cipher,
) -> G1Projective {
    let default_commitment = G1Affine::identity();
    let default_messages = vec![];

    let commitment = commitment.unwrap_or(&default_commitment);
    let messages = messages.unwrap_or(&default_messages);

    // Deserialization:
    //
    // 1. L := len(messages).
    // 2. If len(generators) != L + 1, return INVALID.
    // 3. (Q_1, H_1, ..., H_L) := generators.
    // 4. (msg_1, ..., msg_L) := messages.

    let l = messages.len();
    if generators.len() != l + 1 {
        panic!("the number of generators must be equal to the number of messages plus one");
    }
    let h_points = &generators[1..];

    // Procedure:
    //
    // 1. B := P_1 + H_1 * msg_1 + ... + H_L * msg_L + commitment.
    // 2. If B is the Identity_G1 point, return INVALID.
    // 3. Return B.

    let p_1: G1Affine = G1Affine::from_compressed(&cipher.singularity).unwrap();
    let mut b: G1Projective = h_points
        .iter()
        .zip(messages.iter())
        .fold(p_1.into(), |acc: G1Projective, (h, msg)| {
            (acc + h * msg).into()
        });
    b += commitment;
    if b == G1Projective::identity() {
        panic!("the B value must not be the Identity_G1 point");
    }

    b
}

/// Calculate the blind challenge for the proof of knowledge of a signature.
///
/// - `c`: a point from the G1 group.
/// - `c_bar`: a point from the G1 group.
/// - `generators`: a list of at least one point from the G1 group.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: the cipher suite.
///
/// Return a scalar value as the blind challenge.
pub fn calculate_blind_challenge(
    c: &G1Affine,
    c_bar: &G1Affine,
    generators: &Vec<G1Affine>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> Scalar {
    let api_id = api_id.unwrap_or(&[]);

    // Definitions:
    //
    // - hash_to_scalar_dst: an octet string representing the domain separation tag: "<api_id> || H2S_".

    let hash_to_scalar_dst = [api_id, PADDING_HASH_TO_SCALAR].concat();

    // Deserialization:
    //
    // 1. If len(generators) < 1, return INVALID.
    // 2. M := len(generators) - 1.

    if generators.len() < 1 {
        panic!("The number of generators must be at least one");
    }
    let m = generators.len() - 1;

    // Procedure:
    //
    // 1. c_arr := (M).
    // 2. c_arr.append(generators).
    // 3. c_octets := serialize(c_arr.append(c, c_bar)).
    // 4. Return hash_to_scalar(c_octets, hash_to_scalar_dst).

    let m_bytes = (m as u64).serialize();
    let generators_bytes: Vec<u8> = generators.iter().flat_map(|g| g.serialize()).collect();
    let c_bytes = c.serialize();
    let c_bar_bytes = c_bar.serialize();
    let c_octets = [m_bytes, generators_bytes, c_bytes, c_bar_bytes].concat();

    hash_to_scalar(&c_octets, &hash_to_scalar_dst, cipher)
}
