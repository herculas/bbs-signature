import { Cipher } from "../suite/cipher.ts"
import { concatenate } from "../utils/format.ts"
import { createGenerators, messagesToScalars } from "../utils/interface.ts"
import { prove as coreProve, verify as coreVerify } from "./core.ts"

/**
 * Create a BBS proof, which is a zero-knowledge proof, i.e., a proof-of-knowledge of a BBS signature, while optionally
 * disclosing any subset of the signed messages.
 *
 * Other than the signer's public key, the BBS signature and the signed header and messages, the operation also accepts
 * a presentation header, which will be bound to the resulting proof. To indicate which of the messages are to be
 * disclosed, the operation accepts a list of integers in ascending order, representing the indexes of those messages.
 *
 * @param {Uint8Array} publicKey An octet string representing the public key.
 * @param {Uint8Array} signature An octet string representing the signature.
 * @param {Uint8Array} [header] An octet string containing context and application specific information.
 * @param {Uint8Array} [presentationHeader] An octet string containing the presentation header.
 * @param {Array<Uint8Array>} [messages] A vector of scalars representing the messages.
 * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {Uint8Array} A proof.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-proof-generation-proofgen
 */
export function prove(
  publicKey: Uint8Array,
  signature: Uint8Array,
  header: Uint8Array = new Uint8Array(),
  presentationHeader: Uint8Array = new Uint8Array(),
  messages: Array<Uint8Array> = new Array<Uint8Array>(),
  disclosedIndexes: Array<number> = new Array<number>(),
  cipher: Cipher,
): Uint8Array {
  /**
   * Parameters:
   *
   * - api_id: an octet string <ciphersuite_id> || "H2G_HM2S_", where <ciphersuite_id> is defined by the cipher suite.
   */
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))

  /**
   * Procedure:
   *
   * 1. message_scalars := message_to_scalars(messages, api_id).
   * 2. generators := create_generators(len(messages) + 1, api_id).
   * 3. proof := core_prove(
   *         public_key,
   *         signature,
   *         generators,
   *         header,
   *         presentation_header,
   *         message_scalars,
   *         disclosed_indexes,
   *         api_id,
   *         cipher).
   * 4. If proof is INVALID, return INVALID.
   * 5. Return proof.
   */
  const messageScalars = messagesToScalars(messages, apiId, cipher)
  const generators = createGenerators(messages.length + 1, apiId, cipher)
  return coreProve(
    publicKey,
    signature,
    generators,
    header,
    presentationHeader,
    messageScalars,
    disclosedIndexes,
    apiId,
    cipher,
  )
}

/**
 * Validate a BBS proof, given the signer's public key, a header, a presentation header, the disclosed messages, and the
 * indexes of those messages in the original vector of signed messages.
 *
 * Validating the proof guarantees authenticity and integrity of the header and disclosed messages, as well as knowledge
 * of a valid BBS signature.
 *
 * @param {Uint8Array} publicKey An octet string representing the public key.
 * @param {Uint8Array} proof An octet string representing the proof.
 * @param {Uint8Array} [header] An octet string containing context and application specific information.
 * @param {Uint8Array} [presentationHeader] An octet string containing the presentation header.
 * @param {Array<Uint8Array>} [disclosedMessages] A vector of octet strings representing the disclosed messages.
 * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {boolean} `true` if the proof is valid, `false` otherwise.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-proof-verification-proofver
 */
export function verify(
  publicKey: Uint8Array,
  proof: Uint8Array,
  header: Uint8Array = new Uint8Array(),
  presentationHeader: Uint8Array = new Uint8Array(),
  disclosedMessages: Array<Uint8Array> = new Array<Uint8Array>(),
  disclosedIndexes: Array<number> = new Array<number>(),
  cipher: Cipher,
): boolean {
  /**
   * Parameters:
   *
   * - api_id: an octet string <ciphersuite_id> || "H2G_HM2S_", where <ciphersuite_id> is defined by the cipher suite.
   * - octet_point_length: the length of the octet string representation of a point in G1.
   * - octet_scalar_length: the length of the octet string representation of a scalar.
   */
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))

  /**
   * Deserialization:
   *
   * 1. proof_len_floor := 3 * octet_point_length + 4 * octet_scalar_length.
   * 2. If len(proof) < proof_len_floor, return INVALID.
   * 3. U := floor((len(proof) - proof_len_floor) / octet_scalar_length).
   * 4. R := len(disclosed_indexes).
   */
  const proofLengthFloor = 3 * cipher.octetPointLength + 4 * cipher.octetScalarLength
  if (proof.length < proofLengthFloor) {
    throw new Error("Invalid proof length")
  }
  const remainder = proof.length - proofLengthFloor
  if (remainder % cipher.octetScalarLength !== 0) {
    throw new Error("Invalid proof length")
  }
  const u = remainder / cipher.octetScalarLength
  const r = disclosedIndexes.length

  /**
   * Procedure:
   *
   * 1. message_scalars := message_to_scalars(disclosed_messages, api_id).
   * 2. generators := create_generators(U + R + 1, api_id).
   * 3. result := core_verify(
   *         public_key,
   *         proof,
   *         generators,
   *         header,
   *         presentation_header,
   *         message_scalars,
   *         disclosed_indexes,
   *         api_id,
   *         cipher).
   * 4. Return result.
   */
  const messageScalars = messagesToScalars(disclosedMessages, apiId, cipher)
  const generators = createGenerators(u + r + 1, apiId, cipher)
  return coreVerify(
    publicKey,
    proof,
    generators,
    header,
    presentationHeader,
    messageScalars,
    disclosedIndexes,
    apiId,
    cipher,
  )
}
