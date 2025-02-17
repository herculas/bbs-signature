import {
  prove as core_prove,
  sign as core_sign,
  validate as core_validate,
  verify as core_verify,
} from "../pkg/bbs_signature.js"

import * as assert from "./assertion.ts"
import * as CONSTANT from "./constants.ts"

/**
 * Generate a BBS Signature from a secret key, over a header and a set of messages.
 *
 * @param {string} secretKey A string representing the secret key.
 * @param {string} publicKey A string representing the public key.
 * @param {string} [header] A string containing context and application specific information.
 * @param {Array<string>} [messages] A vector of hex-encoded strings representing the messages.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {string} A signature encoded as a string.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-signature-generation-sign
 */
export function sign(
  secretKey: string,
  publicKey: string,
  header?: string,
  messages?: Array<string>,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): string {
  // existence check
  assert.exist(secretKey, "The secret key must be provided.")
  assert.exist(publicKey, "The public key must be provided.")

  // hex string check
  assert.isValidString(secretKey, "The secret key must be a valid hex string.")
  assert.isValidString(publicKey, "The public key must be a valid hex string.")
  assert.isValidString(header, "The header must be a valid hex string.")
  if (messages) messages.forEach((message) => assert.isValidString(message, "The messages must be valid hex strings."))

  // cipher check
  assert.cipher(cipher)

  // length check
  assert.length(
    secretKey,
    CONSTANT.LENGTH_SECRET_KEY,
    `The secret key must be ${CONSTANT.LENGTH_SECRET_KEY / 2} bytes long.`,
  )
  assert.length(
    publicKey,
    CONSTANT.LENGTH_PUBLIC_KEY,
    `The public key must be ${CONSTANT.LENGTH_PUBLIC_KEY / 2} bytes long.`,
  )

  return core_sign(secretKey, publicKey, header, messages, cipher)
}

/**
 * Validate a BBS Signature, given a public key, a header, and a set of messages.
 *
 * @param {string} publicKey A string representing the public key.
 * @param {string} signature A string representing the signature.
 * @param {string} [header] A string containing context and application specific information.
 * @param {Array<string>} [messages] A vector of strings representing the messages.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {boolean} `true` if the signature is valid, `false` otherwise.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-signature-verification-veri
 */
export function verify(
  publicKey: string,
  signature: string,
  header?: string,
  messages?: Array<string>,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): boolean {
  // existence check
  assert.exist(publicKey, "The public key must be provided.")
  assert.exist(signature, "The signature must be provided.")

  // hex string check
  assert.isValidString(publicKey, "The public key must be a valid hex string.")
  assert.isValidString(signature, "The signature must be a valid hex string.")
  assert.isValidString(header, "The header must be a valid hex string.")
  if (messages) messages.forEach((message) => assert.isValidString(message, "The messages must be valid hex strings."))

  // cipher check
  assert.cipher(cipher)

  // length check
  assert.length(
    publicKey,
    CONSTANT.LENGTH_PUBLIC_KEY,
    `The public key must be ${CONSTANT.LENGTH_PUBLIC_KEY / 2} bytes long.`,
  )
  assert.length(
    signature,
    CONSTANT.LENGTH_SIGNATURE,
    `The signature must be ${CONSTANT.LENGTH_SIGNATURE / 2} bytes long.`,
  )

  return core_verify(publicKey, signature, header, messages, cipher)
}

/**
 * Create a BBS proof, which is a zero-knowledge proof, i.e., a proof-of-knowledge of a BBS signature, while optionally
 * disclosing any subset of the signed messages.
 *
 * Other than the signer's public key, the BBS signature and the signed header and messages, the operation also accepts
 * a presentation header, which will be bound to the resulting proof. To indicate which of the messages are to be
 * disclosed, the operation accepts a list of integers in ascending order, representing the indexes of those messages.
 *
 * @param {string} publicKey A string representing the public key.
 * @param {string} signature A string representing the signature.
 * @param {string} [header] A string containing context and application specific information.
 * @param {string} [presentationHeader] A string containing the presentation header.
 * @param {Array<string>} [messages] A vector of strings representing the messages.
 * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {string} A hex-encoded proof.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-proof-generation-proofgen
 */
export function prove(
  publicKey: string,
  signature: string,
  header?: string,
  presentationHeader?: string,
  messages?: Array<string>,
  disclosedIndexes?: Array<number>,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): string {
  // existence check
  assert.exist(publicKey, "The public key must be provided.")
  assert.exist(signature, "The signature must be provided.")

  // hex string check
  assert.isValidString(publicKey, "The public key must be a valid hex string.")
  assert.isValidString(signature, "The signature must be a valid hex string.")
  assert.isValidString(header, "The header must be a valid hex string.")
  assert.isValidString(presentationHeader, "The presentation header must be a valid hex string.")
  if (messages) messages.forEach((message) => assert.isValidString(message, "The messages must be valid hex strings."))

  // cipher check
  assert.cipher(cipher)

  // length check
  assert.length(
    publicKey,
    CONSTANT.LENGTH_PUBLIC_KEY,
    `The public key must be ${CONSTANT.LENGTH_PUBLIC_KEY / 2} bytes long.`,
  )
  assert.length(
    signature,
    CONSTANT.LENGTH_SIGNATURE,
    `The signature must be ${CONSTANT.LENGTH_SIGNATURE / 2} bytes long.`,
  )

  // index check
  assert.isValidIndexes(
    disclosedIndexes,
    messages?.length,
    "The disclosed indexes must be in ascending order and within bounds.",
  )

  return core_prove(publicKey, signature, header, presentationHeader, messages, disclosedIndexes, cipher)
}

/**
 * Validate a BBS proof, given the signer's public key, a header, a presentation header, the disclosed messages, and the
 * indexes of those messages in the original vector of signed messages.
 *
 * Validating the proof guarantees authenticity and integrity of the header and disclosed messages, as well as knowledge
 * of a valid BBS signature.
 *
 * @param {string} publicKey A string representing the public key.
 * @param {string} proof A string representing the proof.
 * @param {string} [header] A string containing context and application specific information.
 * @param {string} [presentationHeader] A string containing the presentation header.
 * @param {Array<string>} [disclosedMessages] A vector of strings representing the disclosed messages.
 * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {boolean} `true` if the proof is valid, `false` otherwise.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-proof-verification-proofver
 */
export function validate(
  publicKey: string,
  proof: string,
  header?: string,
  presentationHeader?: string,
  disclosedMessages?: Array<string>,
  disclosedIndexes?: Array<number>,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): boolean {
  // existence check
  assert.exist(publicKey, "The public key must be provided.")
  assert.exist(proof, "The proof must be provided.")

  // hex string check
  assert.isValidString(publicKey, "The public key must be a valid hex string.")
  assert.isValidString(proof, "The proof must be a valid hex string.")
  assert.isValidString(header, "The header must be a valid hex string.")
  assert.isValidString(presentationHeader, "The presentation header must be a valid hex string.")
  if (disclosedMessages) {
    disclosedMessages.forEach((message) =>
      assert.isValidString(message, "The disclosed messages must be valid hex strings.")
    )
  }

  // cipher check
  assert.cipher(cipher)

  // length check
  assert.length(
    publicKey,
    CONSTANT.LENGTH_PUBLIC_KEY,
    `The public key must be ${CONSTANT.LENGTH_PUBLIC_KEY / 2} bytes long.`,
  )
  assert.minLength(
    proof,
    CONSTANT.LENGTH_MINIMUM_PROOF,
    `The proof must be at least ${CONSTANT.LENGTH_MINIMUM_PROOF / 2} bytes long.`,
  )

  // index check
  assert.equal(
    disclosedMessages?.length,
    disclosedIndexes?.length,
    "The length of the disclosed messages and indexes must be equal.",
  )

  return core_validate(publicKey, proof, header, presentationHeader, disclosedMessages, disclosedIndexes, cipher)
}
