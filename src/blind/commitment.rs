use crate::blind::core::{commit, commit_verify};
use crate::blind::octets_to_commitment_with_proof;
use crate::suite::cipher::Cipher;
use crate::suite::constants::PADDING_BLIND;
use crate::utils::generator::create_generators;
use crate::utils::scalar::messages_to_scalars;
use bls12_381::{G1Affine, Scalar};

/// Create a commitment to a set of messages that the prover intend to include in the blind signature. This operation
/// returns both the serialized combination of the commitment and its proof of correctness, as well as the random scalar
/// used to blind the commitment.
///
/// - `committed_messages`: a list of octet strings containing the messages to be committed.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return a tuple comprising from an octet string and a random scalar in that order.
pub(super) fn commit_messages(
    committed_messages: Option<&Vec<&[u8]>>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> (Vec<u8>, Scalar) {
    let empty_committed_message_vec = vec![];
    let inner_committed_messages = committed_messages.unwrap_or(&empty_committed_message_vec);

    // Procedure:
    //
    // 1. committed_message_scalars := messages_to_scalars(committed_messages, api_id).
    // 2. blind_generators := create_generators(len(committed_message_scalars) + 1, "BLIND_" || api_id).
    // 3. return core_commit(committed_message_scalars, blind_generators, api_id).
    let committed_message_scalars = messages_to_scalars(inner_committed_messages, api_id, cipher);

    let l = committed_message_scalars.len() + 1;
    let blind_generator_dst = [PADDING_BLIND, api_id.unwrap_or(&[])].concat();
    let blind_generators = create_generators(l, Some(&blind_generator_dst), cipher);
    commit(
        &blind_generators,
        Some(&committed_message_scalars),
        api_id,
        cipher,
    )
}

/// Validate an optional commitment. If a commitment is not supplied, or if it is the Identity_G1 point, this operation
/// will return the Identity_G1 as the default commitment point, which will be ignored by all computations during blind
/// signing.
///
/// - `commitment_with_proof`: an octet string representing the commitment and its proof of correctness.
/// - `blind_generators`: a list of points from the G1 group.
/// - `api_id`: an octet string representing the API identifier.
/// - `cipher`: a cipher suite.
///
/// Return a point from the G1 group as the commitment.
pub(super) fn deserialize_and_validate_commit(
    commitment_with_proof: Option<&[u8]>,
    blind_generators: Option<&Vec<G1Affine>>,
    api_id: Option<&[u8]>,
    cipher: &Cipher,
) -> G1Affine {
    if commitment_with_proof.is_none() || commitment_with_proof.unwrap().is_empty() {
        return G1Affine::identity();
    };

    let blind_generators_empty_vec = vec![];
    let inner_commitment_with_proof = commitment_with_proof.unwrap();
    let inner_blind_generators = blind_generators.unwrap_or(&blind_generators_empty_vec);

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

    let (commit, commit_proof) = octets_to_commitment_with_proof(&inner_commitment_with_proof);

    if commit_proof.m_hats.len() + 1 != inner_blind_generators.len() {
        return G1Affine::identity();
    };

    let validation_res = commit_verify(
        &commit,
        &commit_proof,
        inner_blind_generators,
        api_id,
        cipher,
    );
    if validation_res == false {
        panic!("The commitment is invalid.");
    }
    commit
}
