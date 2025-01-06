import { Cipher } from "../suite/cipher.ts"
import { G1Projective, Scalar } from "../suite/elements.ts"
import { randomScalars } from "../utils/random.ts"
import { octetsToProof, octetsToPublicKey, octetsToSignature } from "../utils/serialize.ts"
import { challenge, finalize, init, prepare } from "./subroutines.ts"

/**
 * Compute a zero-knowledge proof-of-knowledge of a signature, while optionally selectively disclosing from the original
 * set of signed messages. The prover may also supply a presentation header.
 *
 * The messages supplied in this operation MUST be in the same order as when signed. To specify which of those messages
 * will be disclosed, the prover can supply the list of indexes that the disclosed messages have in the array of signed
 * messages.
 *
 * @param {Uint8Array} publicKey An octet string representing the public key.
 * @param {Uint8Array} signature An octet string representing the signature.
 * @param {Array<G1Projective>} generators A vector of pseudo-random points in G1.
 * @param {Uint8Array} [header] An octet string containing context and application specific information.
 * @param {Uint8Array} [presentationHeader] An octet string containing the presentation header.
 * @param {Array<Scalar>} [messages] A vector of scalars representing the messages.
 * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
 * @param {Uint8Array} [apiId] An octet string containing the API identifier.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {Uint8Array} A proof.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-coreproofgen
 */
export function prove(
  publicKey: Uint8Array,
  signature: Uint8Array,
  generators: Array<G1Projective>,
  header: Uint8Array = new Uint8Array(),
  presentationHeader: Uint8Array = new Uint8Array(),
  messages: Array<Scalar> = new Array<Scalar>(),
  disclosedIndexes: Array<number> = new Array<number>(),
  apiId: Uint8Array = new Uint8Array(),
  cipher: Cipher,
): Uint8Array {
  /**
   * Deserialization:
   *
   * 1. signature_result := octets_to_signature(signature).
   * 2. If signature_result is INVALID, return INVALID.
   * 3. (A, e) := signature_result.
   *
   * 4. L := len(messages).
   * 5. R := len(disclosed_indexes).
   * 6. If R > L, return INVALID.
   * 7. U := L - R.
   * 8. For i in disclosed_indexes: if i < 0 or i > L - 1, return INVALID.
   * 9. undisclosed_indexes := (0, 1, ..., L - 1) \ disclosed_indexes.
   * 10. (i_1, i_2, ..., i_R) := disclosed_indexes.
   * 11. (j_1, j_2, ..., j_U) := undisclosed_indexes.
   *
   * 12. disclosed_messages := (messages[i_1], messages[i_2], ..., messages[i_R]).
   * 13. undisclosed_messages := (messages[j_1], messages[j_2], ..., messages[j_U]).
   */
  const [a, e] = octetsToSignature(signature, cipher)

  const l = messages.length
  const r = disclosedIndexes.length
  if (r > l) {
    throw new Error("Invalid disclosed indexes")
  }
  const u = l - r
  if (disclosedIndexes.some((i) => i < 0 || i > l - 1)) {
    throw new Error("Invalid disclosed indexes")
  }

  const undisclosedIndexes = Array.from({ length: l }, (_, i) => i).filter((i) => !disclosedIndexes.includes(i))
  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const undisclosedMessages = undisclosedIndexes.map((i) => messages[i])

  /**
   * Procedure:
   *
   * 1. random_scalars := calculate_random_scalars(U + 5).
   * 2. init_res := proof_init(
   *         public_key,
   *         signature_result,
   *         generators,
   *         random_scalars,
   *         header,
   *         messages,
   *         undisclosed_indexes,
   *         api_id).
   * 3. If init_res is INVALID, return INVALID.
   * 4. challenge := proof_challenge_calculate(init_res, disclosed_indexes, disclosed_messages, presentation_header).
   * 5. If challenge is INVALID, return INVALID.
   * 6. proof := proof_finalize(init_res, challenge, e, random_scalars, undisclosed_messages).
   */
  const randoms = randomScalars(u + 5, cipher)
  const initRes = init(publicKey, [a, e], generators, randoms, header, messages, undisclosedIndexes, apiId, cipher)
  const c = challenge(initRes, disclosedMessages, disclosedIndexes, presentationHeader, apiId, cipher)
  return finalize(initRes, c, e, randoms, undisclosedMessages, cipher)
}

/**
 * Check that a proof is valid for a header, vector of disclosed messages, along side their index corresponding to their
 * original position when signed and presentation header against a public key. Validating this proof guarantees the
 * authenticity and integrity of the header and disclosed messages, as well as knowledge of a valid BBS signature.
 *
 * The inputted disclosed messages MUST be supplied to this operation in the same order as they were signed. Similarly,
 * the indexes of the disclosed messages MUST be in the same order as the disclosed indexes during proof generation.
 *
 * @param {Uint8Array} publicKey An octet string representing the public key.
 * @param {Uint8Array} proof An octet string of the proof.
 * @param {Array<G1Projective>} generators A vector of pseudo-random points in G1.
 * @param {Uint8Array} [header] An octet string containing context and application specific information.
 * @param {Uint8Array} [presentationHeader] An octet string containing the presentation header.
 * @param {Array<Scalar>} [disclosedMessages] A vector of scalars representing the disclosed messages.
 * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
 * @param {Uint8Array} [apiId] An octet string containing the API identifier.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {boolean} `true` if the proof is valid, `false` otherwise.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-coreproofverify
 */
export function verify(
  publicKey: Uint8Array,
  proof: Uint8Array,
  generators: Array<G1Projective>,
  header: Uint8Array = new Uint8Array(),
  presentationHeader: Uint8Array = new Uint8Array(),
  disclosedMessages: Array<Scalar> = new Array<Scalar>(),
  disclosedIndexes: Array<number> = new Array<number>(),
  apiId: Uint8Array = new Uint8Array(),
  cipher: Cipher,
): boolean {
  /**
   * Deserialization:
   *
   * 1. proof_result := octets_to_proof(proof).
   * 2. If proof_result is INVALID, return INVALID.
   * 3. (A_bar, B_bar, D, hat_e, hat_r_1, hat_r_3, commitments, cp) := proof_result.
   * 4. W := octet_to_pubkey(public_key).
   */
  const proofResult = octetsToProof(proof, cipher)
  const [aBar, bBar] = proofResult
  const cp = proofResult.at(-1)
  const w = octetsToPublicKey(publicKey, cipher)

  /**
   * Procedure:
   *
   * 1. init_res := proof_verify_init(
   *         public_key,
   *         proof_result,
   *         generators,
   *         header,
   *         messages,
   *         disclosed_indexes,
   *         api_id).
   * 2. If init_res is INVALID, return INVALID.
   * 3. challenge := proof_challenge_calculate(init_res, disclosed_indexes, disclosed_messages, presentation_header).
   * 4. If challenge is INVALID, return INVALID.
   * 5. If cp != challenge, return INVALID.
   * 6. If h(A_bar, W) * h(B_bar, g_2) != Identity_GT, return INVALID.
   * 7. Return VALID.
   */
  const initRes = prepare(
    publicKey,
    proofResult,
    generators,
    header,
    disclosedMessages,
    disclosedIndexes,
    apiId,
    cipher,
  )
  const c = challenge(initRes, disclosedMessages, disclosedIndexes, presentationHeader, apiId, cipher)
  if (c !== cp) {
    return false
  }

  const pair1 = cipher.pairing(aBar, w)
  const pair2 = cipher.pairing(bBar, cipher.types.G2.BASE.negate())
  return cipher.pairingCompare(pair1, pair2, cipher.types.Fpt.ONE)
}
