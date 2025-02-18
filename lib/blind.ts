/**
 * Blind BBS signing and verifying operations, as well as blind BBS proof generation and validation.
 * @module blind
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-00
 */

import { blind_messages, blind_prove, blind_sign, blind_validate, blind_verify } from "../pkg/bbs_signature.js"

import * as CONSTANT from "./constants.ts"

/**
 * Commit to a set of messages by the prover to blind these messages before sending them to the signer. Note that this
 * operation returns both the serialized combination of the commitment and its proof-of-correctness, as well as the
 * random scalar used to blind the commitment.
 *
 * @memberof blind
 *
 * @param {Array<string>} [committedMessages] A vector of octet strings.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {string} A serialized commitment and its proof-of-correctness, along with a secret prover blindness.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-00#name-commitment-computation
 */
export function commit(
  committedMessages?: Array<string>,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): {
  commitmentWithProof: string
  proverBlindness: string
} {
  const res = blind_messages(committedMessages, cipher)
  const commitmentWithProof = res.slice(0, -CONSTANT.LENGTH_SCALAR)
  const proverBlindness = res.slice(-CONSTANT.LENGTH_SCALAR)

  return {
    commitmentWithProof,
    proverBlindness,
  }
}

/**
 * Calculate a blind BBS signature from a secret key, over a header, a set of messages, and potentially a commitment. If
 * supplied, the commitment MUST be accompanied by its proof-of-correctness.
 *
 * @memberof blind
 *
 * @param {string} secretKey A string representing the secret key.
 * @param {string} publicKey A string representing the public key.
 * @param {string} [commitmentWithProof] A octet string, representing a serialized commitment and proof.
 * @param {string} [header] A string containing context and application specific information.
 * @param {Array<string>} [messages] A vector of hex-encoded strings representing the messages.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {string} A signature encoded as a string.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-00#name-blind-signature-generation
 */
export function sign(
  secretKey: string,
  publicKey: string,
  commitmentWithProof?: string,
  header?: string,
  messages?: Array<string>,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): string {
  return blind_sign(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
}

/**
 * Verify a blind BBS signature, given the signer's public key, a header, a set of messages known to the signer, and if
 * used, a set of committed messages, along with the prover blindness as returned by the `blindMessages` operation.
 *
 * @memberof blind
 *
 * @param {string} publicKey A string representing the public key.
 * @param {string} signature A string representing the signature.
 * @param {string} [header] A string containing context and application specific information.
 * @param {Array<string>} [messages] A vector of strings representing the messages.
 * @param {Array<string>} [committedMessages] A vector of octet strings representing the committed messages.
 * @param {string} [proverBlindness] A string representing the secret prover blindness.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {boolean} `true` if the signature is valid, `false` otherwise.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-00#name-blind-signature-verificatio
 */
export function verify(
  publicKey: string,
  signature: string,
  header?: string,
  messages?: Array<string>,
  committedMessages?: Array<string>,
  proverBlindness?: string,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): boolean {
  return blind_verify(publicKey, signature, header, messages, committedMessages, proverBlindness, cipher)
}

/**
 * Create a blind BBS proof, which is a zero-knowledge proof-of-knowledge of a BBS signature, while optionally
 * disclosing any subset of the signed messages.
 *
 * Note that in contrast to the basic `prove` operation, this operation accepts two different list of messages and
 * disclosed indexes, one for the messages known to the signer, and the corresponding disclosed indexes, and one for the
 * messages committed by the prover, and the corresponding disclosed indexes.
 *
 * Furthermore, this operation also expects a secret prover blindness (as returned from the `blindMessages` operation).
 * If the BBS signature is generated using a commitment value, then the prover blindness used to generate the commitment
 * SHOULD be provided to this operation, otherwise the resulting proof will be invalid.
 *
 * @memberof blind
 *
 * @param {string} publicKey A string representing the public key.
 * @param {string} signature A string representing the signature.
 * @param {string} [header] A string containing context and application specific information.
 * @param {string} [presentationHeader] A string containing the presentation header.
 * @param {Array<string>} [messages] A vector of strings representing the messages.
 * @param {Array<string>} [committedMessages] A vector of octet strings representing the committed messages.
 * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
 * @param {Array<number>} [disclosedCommitmentIndexes] Integers representing the indexes of the disclosed commitments.
 * @param {string} [proverBlindness] A string representing the secret prover blindness.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {string} A hex-encoded proof.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-00#name-proof-generation
 */
export function prove(
  publicKey: string,
  signature: string,
  header?: string,
  presentationHeader?: string,
  messages?: Array<string>,
  committedMessages?: Array<string>,
  disclosedIndexes?: Array<number>,
  disclosedCommitmentIndexes?: Array<number>,
  proverBlindness?: string,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): string {
  return blind_prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )
}

/**
 * Validate a blind BBS proof, given the signer's public key, a header, a presentation header, two arrays if disclosed
 * messages (the ones known to the signer, and the ones committed by the prover), and two corresponding arrays of
 * indexes those messages had in the original vectors of signed messages.
 *
 * In addition, this operation accepts an integer `l`, representing the total number of signed messages known to the
 * signer.
 *
 * @memberof blind
 *
 * @param {string} publicKey A string representing the public key.
 * @param {string} proof A string representing the proof.
 * @param {string} [header] A string containing context and application specific information.
 * @param {string} [presentationHeader] A string containing the presentation header.
 * @param {number} [l] The total number of signer known messages. If not specified, it defaults to 0.
 * @param {Array<string>} [disclosedMessages] A vector of strings representing the disclosed messages.
 * @param {Array<string>} [disclosedCommitmentMessages] Strings representing the disclosed commitment messages.
 * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
 * @param {Array<number>} [disclosedCommitmentIndexes] Integers representing the indexes of the disclosed commitments.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {boolean} `true` if the proof is valid, `false` otherwise.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-00#name-proof-verification
 */
export function validate(
  publicKey: string,
  proof: string,
  header?: string,
  presentationHeader?: string,
  l?: number,
  disclosedMessages?: Array<string>,
  disclosedCommitmentMessages?: Array<string>,
  disclosedIndexes?: Array<number>,
  disclosedCommitmentIndexes?: Array<number>,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): boolean {
  return blind_validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    l,
    disclosedMessages,
    disclosedCommitmentMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )
}
