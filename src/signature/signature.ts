import { Cipher } from "../suite/cipher.ts"
import { Scalar } from "../suite/elements.ts"
import { concatenate } from "../utils/format.ts"
import { createGenerators, messagesToScalars } from "../utils/interface.ts"
import { sign as coreSign, verify as coreVerify } from "./core.ts"

/**
 * Generate a BBS Signature from a secret key, over a header and a set of messages.
 *
 * @param {Scalar} secretKey A scalar representing the secret key.
 * @param {Uint8Array} publicKey An octet string representing the public key.
 * @param {Uint8Array} header An octet string containing context and application specific information.
 * @param {Array<Uint8Array>} messages A vector of scalars representing the messages.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {Uint8Array} A signature encoded as an octet string.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-signature-generation-sign
 */
export function sign(
  secretKey: Scalar,
  publicKey: Uint8Array,
  header: Uint8Array = new Uint8Array(),
  messages: Array<Uint8Array> = new Array<Uint8Array>(),
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
   * 3. signature := core_sign(secret_key, public_key, generators, header, message_scalars, api_id, cipher).
   * 4. If signature is INVALID, return INVALID.
   * 5. Return signature.
   */
  const messageScalars = messagesToScalars(messages, apiId, cipher)
  const generators = createGenerators(messages.length + 1, apiId, cipher)
  return coreSign(secretKey, publicKey, generators, header, messageScalars, apiId, cipher)
}

/**
 * Validate a BBS Signature, given a public key, a header, and a set of messages.
 *
 * @param {Uint8Array} publicKey An octet string representing the public key.
 * @param {Uint8Array} signature An octet string representing the signature.
 * @param {Uint8Array} header An octet string containing context and application specific information.
 * @param {Array<Uint8Array>} messages A vector of octet strings representing the messages.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {boolean} `true` if the signature is valid, `false` otherwise.
 * 
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-signature-verification-veri
 */
export function verify(
  publicKey: Uint8Array,
  signature: Uint8Array,
  header: Uint8Array = new Uint8Array(),
  messages: Array<Uint8Array> = new Array<Uint8Array>(),
  cipher: Cipher,
): boolean {
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
   * 3. result := core_verify(public_key, signature, generators, header, message_scalars, api_id, cipher).
   * 4. Return result.
   */
  const messageScalars = messagesToScalars(messages, apiId, cipher)
  const generators = createGenerators(messages.length + 1, apiId, cipher)
  return coreVerify(publicKey, signature, generators, header, messageScalars, apiId, cipher)
}
