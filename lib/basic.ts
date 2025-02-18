import {
  prove as core_prove,
  sign as core_sign,
  validate as core_validate,
  verify as core_verify,
} from "../pkg/bbs_signature.js"

import * as CONSTANT from "./constants.ts"

/**
 * Basic BBS signing and verifying operations, as well as BBS proof generation and validation.
 * @namespace basic
 * 
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07
 */

/**
 * Generate a BBS Signature from a secret key, over a header and a set of messages.
 * 
 * @memberof basic
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
  return core_sign(secretKey, publicKey, header, messages, cipher)
}

/**
 * Validate a BBS Signature, given a public key, a header, and a set of messages.
 * 
 * @memberof basic
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
 * @memberof basic
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
  return core_prove(publicKey, signature, header, presentationHeader, messages, disclosedIndexes, cipher)
}

/**
 * Validate a BBS proof, given the signer's public key, a header, a presentation header, the disclosed messages, and the
 * indexes of those messages in the original vector of signed messages.
 *
 * Validating the proof guarantees authenticity and integrity of the header and disclosed messages, as well as knowledge
 * of a valid BBS signature.
 * 
 * @memberof basic
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
  return core_validate(publicKey, proof, header, presentationHeader, disclosedMessages, disclosedIndexes, cipher)
}
