import { Cipher } from "../types/cipher.ts"
import { G1Projective } from "../types/elements.ts"
import { calculateDomain } from "../utils/domain.ts"
import { concatenate } from "../utils/format.ts"
import { hashToScalar } from "../utils/hash.ts"
import { serialize, signatureToOctets } from "../utils/serialize.ts"
import { Scalar } from "../types/elements.ts"
import { octetsToPublicKey, octetsToSignature } from "../utils/deserialize.ts"

/**
 * Compute a deterministic signature from a secret key, a set of generators, and optionally a header and a vector of
 * messages.
 *
 * @param {Scalar} secretKey A secret key.
 * @param {Uint8Array} publicKey A public key.
 * @param {Array<G1Projective>} generators A vector of pseudo-random points in G1.
 * @param {Uint8Array} [header] An octet string containing context and application specific information.
 * @param {Array<Scalar>} [messages] A vector of scalars representing the messages.
 * @param {Uint8Array} [apiId] An octet string containing the API identifier.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {Uint8Array} A signature.
 *
 * @see https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coresign
 */
export function sign(
  secretKey: Scalar,
  publicKey: Uint8Array,
  generators: Array<G1Projective>,
  header: Uint8Array = new Uint8Array(),
  messages: Array<Scalar> = new Array<Scalar>(),
  apiId: Uint8Array = new Uint8Array(),
  cipher: Cipher,
): Uint8Array {
  /**
   * Definitions
   *
   * - hash_to_scalar_dst: an octet string representing the domain separation tag: api_id || "H2S_"
   */
  const hashToScalarDst = concatenate(apiId, new TextEncoder().encode("H2S_"))
  const field = cipher.types.Fr

  /**
   * Deserialization:
   *
   * 1. L := len(messages)
   * 2. if len(generators) != L + 1, return INVALID
   * 3. (msg_1, msg_2, ..., msg_L) := messages
   * 4. (Q_1, H_1, ..., H_L) := generators
   */
  const length = messages.length
  if (generators.length !== (length + 1)) {
    throw new Error("The number of generators must be equal to the number of messages plus one.")
  }
  const [q1, ...hPoints] = generators

  /**
   * Procedure:
   *
   * 1. domain := calculate_domain(PK, Q_1, (H_1, ..., H_L), header, api_id)
   * 2. e := hash_to_scalar(serialize(SK, msg_1, ..., msg_L, domain), hash_to_scalar_dst)
   * 3. B := P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
   * 4. A := B * (1 / (SK + e))
   * 5. return signature_to_octets(A, e)
   */
  const domain = calculateDomain(publicKey, q1, hPoints, header, apiId, cipher)
  const e = hashToScalar(serialize([secretKey, ...messages, domain], cipher), hashToScalarDst, cipher)
  let b = cipher.p1.add(q1.multiply(domain))
  hPoints.forEach((h, i) => {
    b = b.add(h.multiply(messages[i]))
  })
  const a = b.multiply(field.inv(field.add(secretKey, e)))
  if (a.equals(cipher.types.G1.ZERO)) {
    throw new Error("The signature is invalid.")
  }
  return signatureToOctets([a, e], cipher)
}

/**
 * Check if a signature is valid for a given set of generators, header, and vector of messages, against a public key.
 * The set of messages MUST be supplied in the same order they were supplied to the sign function.
 * 
 * @param {Uint8Array} publicKey An octet string representing the public key.
 * @param {Uint8Array} signature An octet string representing the signature.
 * @param {Array<G1Projective>} generators A vector of pseudo-random points in G1.
 * @param {Uint8Array} [header] An octet string containing context and application specific information.
 * @param {Array} [messages] A vector of scalars representing the messages.
 * @param {Uint8Array} [apiId] An octet string containing the API identifier.
 * @param {Cipher} cipher A cipher suite.
 * 
 * @returns {boolean} True if the signature is valid, false otherwise.
 * 
 * @see https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-coreverify
 */
export function verify(
  publicKey: Uint8Array,
  signature: Uint8Array,
  generators: Array<G1Projective>,
  header: Uint8Array = new Uint8Array(),
  messages: Array<Scalar> = new Array<Scalar>(),
  apiId: Uint8Array = new Uint8Array(),
  cipher: Cipher,
): boolean {
  /**
   * Deserialization:
   * 
   * 1. signature_result = octets_to_signature(signature)
   * 2. If signature_result is INVALID, return INVALID
   * 3. (A, e) := signature_result
   * 4. W = octet_to_pubkey(PK)
   * 5. If W is INVALID, return INVALID
   * 6. L := len(messages)
   * 7. If len(generators) != L + 1, return INVALID
   * 8. (msg_1, msg_2, ..., msg_L) := messages
   * 9. (Q_1, H_1, ..., H_L) := generators
   */

  const [a, e] = octetsToSignature(signature, cipher)
  const w = octetsToPublicKey(publicKey, cipher)
  const length = messages.length
  if (generators.length !== (length + 1)) {
    throw new Error("The number of generators must be equal to the number of messages plus one.")
  }
  const [q1, ...hPoints] = generators

  /**
   * Procedure:
   * 
   * 1. domain := calculate_domain(PK, Q_1, (H_1, ..., H_L), header, api_id)
   * 2. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
   * 3. If h(A, W + BP2 * e) * h(B, -BP2) != Identity_GT, return INVALID
   * 4. return VALID
   */
  const domain = calculateDomain(publicKey, q1, hPoints, header, apiId, cipher)
  let b = cipher.p1.add(q1.multiply(domain))
  hPoints.forEach((h, i) => {
    b = b.add(h.multiply(messages[i]))
  })

  const pair1 = cipher.pairing(a, w.add(cipher.types.G2.BASE.multiply(e)))
  const pair2 = cipher.pairing(b, cipher.types.G2.BASE.negate())
  return cipher.pairingCompare(pair1, pair2, cipher.types.Fpt.ONE)
}
