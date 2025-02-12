use bls12_381::G1Affine;

/// Create a commitment to a set of messages that the prover intend to include in the blind signature. This operation
/// returns both the serialized combination of the commitment and its proof of correctness, as well as the random scalar
/// used to blind the commitment.
///
/// - `committed_messages`: a list of octet strings containing the messages to be committed.
/// - `api_id`: an octet string representing the API identifier.
///
/// Return a tuple comprising from an octet string and a random scalar in that order.
pub(super) fn commit_messages(committed_messages: Option<&Vec<&[u8]>>, api_id: Option<&[u8]>) {
    // Procedure:
    //
    // 1. committed_message_scalars := messages_to_scalars(committed_messages, api_id).
    // 2. blind_generators := create_generators(len(committed_message_scalars) + 1, "BLIND_" || api_id).
    // 3. return core_commit(committed_message_scalars, blind_generators, api_id).
}

/// Validate an optional commitment. If a commitment is not supplied, or if it is the Identity_G1 point, this operation
/// will return the Identity_G1 as the default commitment point, which will be ignored by all computations during blind
/// signing.
///
/// - `commitment_with_proof`: an octet string representing the commitment and its proof of correctness.
/// - `blind_generators`: a list of points from the G1 group.
/// - `api_id`: an octet string representing the API identifier.
///
/// Return a point from the G1 group as the commitment.
pub(super) fn deserialize_and_validate_commit(
    commitment_with_proof: Option<&[u8]>,
    blind_generators: Option<&Vec<G1Affine>>,
    api_id: Option<&[u8]>,
) {
    // Procedure:
    //
    // 1. If commitment_with_proof is the empty string, return Identity_G1.
    // 2. com_res := octets_to_commitment_with_proof(commitment_with_proof).
    // 3. If com_res is INVALID, return INVALID.
    // 4. (commit, commit_proof) := com_res.
    // 5. If len(commit_proof[1]) + 1 != len(blind_generators), return INVALID.
    // 6. validation_res := core_commit_verify(commit, commit_proof, blind_generators, api_id).
    // 7. If validation_res is INVALID, return INVALID.
    // 8. Return commit.
}
