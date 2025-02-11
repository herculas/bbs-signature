use crate::suite::cipher::Cipher;
use bls12_381::Scalar;

/// Calculate a BBS blind signature from a secret key, over a header, a set of messages, and optionally a commitment
/// value. If supplied, the commitment value MUST be accompanied by its proof of correctness (commitment_with_proof, as
/// outputted by the commit operation).
///
/// The blind sign operation makes use of the `finalize_blind_sign` procedure and the calculate_B procedure. The
/// calculate_B procedure is defined to return an array of elements, to establish extendability of the scheme by
/// allowing the calculate_B operation to return more elements than just the point to be signed.
///
/// - `secret_key`: a scalar representing the secret key.
/// - `public_key`: an octet string representing the public key.
/// - `commitment_with_proof`: an octet string, representing a serialized commitment and commitment proof, as the first 
///         element outputted by the commit operation. If not supplied, it defaults to an empty octet string.
/// - `header`: an octet string containing the context and application specific information.
/// - `messages`: a list of octet strings containing the messages to be signed.
/// - `cipher`: a cipher suite.
/// 
/// Return a blind BBS signature.
pub fn sign(
    secret_key: &Scalar,
    public_key: &[u8],
    commitment_with_proof: &[u8],
    header: Option<&[u8]>,
    messages: Option<&Vec<&[u8]>>,
    cipher: &Cipher,
) {
    // Parameters:
    //
    // - api_id: an octet string "<cipher_suite_id> || BLIND_H2G_HM2S_", where <cipher_suite_id> is defined by the
    //      cipher suite and "BLIND_H2G_HM2S_" is an ASCII string composed of 15 bytes.
    
    // Deserialization:
    //
    // 1. L := len(messages).
    // 2. M := len(commitment_with_proof).
    // 3. If M != 0, M := M - octet_point_length - octet_scalar_length.
    // 4. M := M / octet_scalar_length.
    // 5. If M < 0, return INVALID.
    
    // Procedure:
    //
    // 1. generators := create_generators(L + 1, api_id).
    // 2. blind_generators := create_generators(M + 1, "BLIND_", api_id).
    // 3. commit := deserialize_and_validate_commit(commitment_with_proof, blind_generators, api_id).
    // 4. If commit is INVALID, return INVALID.
    // 5. message_scalars := message_to_scalars(messages, cipher).
    // 6. res := calculate_B(generators, commit, message_scalars).
    // 7. If res is INVALID, return INVALID.
    // 8. (B) := res.
    // 9. blind_sig := finalize_blind_sign(secret_key, public_key, B, generators, blind_generators, header, api_id).
    // 10. If blind_sig is INVALID, return INVALID.
    // 11. Return blind_sig.
}
