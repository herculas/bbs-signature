use bls12_381::{G1Affine, Scalar};

/// Prepare the parameters for the proof of knowledge of a signature.
///
/// - `messages`: a list of octet strings. If not supplied, it defaults to an empty list.
/// - `committed_messages`: a list of octet strings. If not supplied, it defaults to an empty list.
/// - `secret_prover_blind`: a scalar value. If not supplied, it defaults to the zero scalar.
/// - `api_id`: an octet string. If not supplied, it defaults to an empty string.
///
/// Return a vector `message_scalars` of scalar values, and a generator vector of points from the G1 group.
pub fn prepare_parameters(
    messages: Option<&Vec<&[u8]>>,
    committed_messages: Option<&Vec<&[u8]>>,
    secret_prover_blind: Option<&Scalar>,
    api_id: Option<&[u8]>,
) {
    // Procedure:
    //
    // 1. message_scalars := message_to_scalars(messages, api_id).
    // 2. committed_message_scalars := [].
    // 3. If secret_prover_blind != None, committed_message_scalars.append(secret_prover_blind).
    // 4. committed_message_scalars.append(message_to_scalars(committed_messages, api_id)).
    // 5. generators := create_generators(generators_number, api_id).
    // 6. blind_generators := create_generators(blind_generator_number, "BLIND_" || api_id).
    // 7. Return (message_scalars.append(committed_message_scalars), generators.append(blind_generators)).
}

/// Calculate the `b` value for the proof of knowledge of a signature.
///
/// - `generators`: a list of at least one point from the G1 group.
/// - `commitment`: a point from the G1 group. If not supplied, it defaults to the Identity_G1 point.
/// - `messages`: a list of scalar values. If not supplied, it defaults to an empty list.
///
/// Return an element from the G1 subgroup, or INVALID.
pub fn calculate_b(
    generators: Vec<G1Affine>,
    commitment: Option<G1Affine>,
    messages: Option<&Vec<Scalar>>,
) {
    // Deserialization:
    //
    // 1. L := len(messages).
    // 2. If len(generators) != L + 1, return INVALID.
    // 3. (Q_1, H_1, ..., H_L) := generators.
    // 4. (msg_1, ..., msg_L) := messages.

    // Procedure:
    //
    // 1. B := Q_1 + H_1 * msg_1 + ... + H_L * msg_L + commitment.
    // 2. If B is the Identity_G1 point, return INVALID.
    // 3. Return B.
}

/// Calculate the blind challenge for the proof of knowledge of a signature.
///
/// - `c`: a point from the G1 group.
/// - `c_bar`: a point from the G1 group.
/// - `generators`: a list of at least one point from the G1 group.
/// - `api_id`: an octet string. If not supplied, it defaults to an empty string.
///
/// Return a scalar value as the blind challenge.
pub fn calculate_blind_challenge(
    c: &G1Affine,
    c_bar: &G1Affine,
    generators: Vec<G1Affine>,
    api_id: Option<&[u8]>,
) {
    // Definitions:
    //
    // - hash_to_scalar_dst: an octet string representing the domain separation tag: "<api_id> || H2S_".

    // Deserialization:
    //
    // 1. If len(generators) < 1, return INVALID.
    // 2. M := len(generators) - 1.

    // Procedure:
    //
    // 1. c_arr := [] of length M.
    // 2. c_arr.append(generators).
    // 3. c_octets := serialize(c_arr.append(c, c_bar)).
    // 4. Return hash_to_scalar(c_octets, hash_to_scalar_dst).
}
