import { blind_messages, blind_prove, blind_sign, blind_validate, blind_verify } from "../../pkg/bbs_signature.js"

import {
  assertCipher,
  assertEquality,
  assertExist,
  assertHexString,
  assertIndexes,
  assertLength,
  assertLengthMin,
} from "../util/assertion.ts"
import { Cipher } from "../constant/cipher.ts"

import * as ALGORITHM_CONSTANT from "../constant/algorithm.ts"

/**
 * Commit to a set of messages by the prover to blind these messages before sending them to the signer. Note that this
 * operation returns both the serialized combination of the commitment and its proof-of-correctness, as well as the
 * random scalar used to blind the commitment.
 *
 * @param {Array<string>} [committedMessages] A vector of octet strings.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {string} A serialized commitment and its proof-of-correctness, along with a secret prover blindness.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-00#name-commitment-computation
 */
export function blindMessages(
  committedMessages?: Array<string>,
  cipher: Cipher = Cipher.XOF_SHAKE_256,
): {
  commitmentWithProof: string
  proverBlindness: string
} {
  // hex string check
  if (committedMessages) {
    committedMessages.forEach((message) =>
      assertHexString(message, "The committed messages must be valid hex strings.")
    )
  }

  // cipher check
  assertCipher(cipher)

  const res = blind_messages(committedMessages, cipher)
  const commitmentWithProof = res.slice(0, -ALGORITHM_CONSTANT.LENGTH_SCALAR)
  const proverBlindness = res.slice(-ALGORITHM_CONSTANT.LENGTH_SCALAR)

  return {
    commitmentWithProof,
    proverBlindness,
  }
}

/**
 * Calculate a blind BBS signature from a secret key, over a header, a set of messages, and potentially a commitment. If
 * supplied, the commitment MUST be accompanied by its proof-of-correctness.
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
export function blindSign(
  secretKey: string,
  publicKey: string,
  commitmentWithProof?: string,
  header?: string,
  messages?: Array<string>,
  cipher: Cipher = Cipher.XOF_SHAKE_256,
): string {
  // existence check
  assertExist(secretKey, "The secret key must be provided.")
  assertExist(publicKey, "The public key must be provided.")

  // hex string check
  assertHexString(secretKey, "The secret key must be a valid hex string.")
  assertHexString(publicKey, "The public key must be a valid hex string.")
  assertHexString(commitmentWithProof, "The commitment with proof must be a valid hex string.")
  assertHexString(header, "The header must be a valid hex string.")
  if (messages) messages.forEach((message) => assertHexString(message, "The messages must be valid hex strings."))

  // cipher check
  assertCipher(cipher)

  // length check
  assertLength(
    secretKey,
    ALGORITHM_CONSTANT.LENGTH_SECRET_KEY,
    `The secret key must be ${ALGORITHM_CONSTANT.LENGTH_SECRET_KEY / 2} bytes long.`,
  )
  assertLength(
    publicKey,
    ALGORITHM_CONSTANT.LENGTH_PUBLIC_KEY,
    `The public key must be ${ALGORITHM_CONSTANT.LENGTH_PUBLIC_KEY / 2} bytes long.`,
  )
  if (commitmentWithProof) {
    assertLengthMin(
      commitmentWithProof,
      ALGORITHM_CONSTANT.LENGTH_MINIMUM_COMMIT_WITH_PROOF,
      `The commitment with proof must be at least ${ALGORITHM_CONSTANT.LENGTH_MINIMUM_COMMIT_WITH_PROOF} bytes long.`,
    )
  }

  return blind_sign(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
}

/**
 * Verify a blind BBS signature, given the signer's public key, a header, a set of messages known to the signer, and if
 * used, a set of committed messages, along with the prover blindness as returned by the `blindMessages` operation.
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
export function blindVerify(
  publicKey: string,
  signature: string,
  header?: string,
  messages?: Array<string>,
  committedMessages?: Array<string>,
  proverBlindness?: string,
  cipher: Cipher = Cipher.XOF_SHAKE_256,
): boolean {
  // existence check
  assertExist(publicKey, "The public key must be provided.")
  assertExist(signature, "The signature must be provided.")

  // hex string check
  assertHexString(publicKey, "The public key must be a valid hex string.")
  assertHexString(signature, "The signature must be a valid hex string.")
  assertHexString(header, "The header must be a valid hex string.")
  assertHexString(proverBlindness, "The prover blindness must be a valid hex string.")
  if (messages) messages.forEach((message) => assertHexString(message, "The messages must be valid hex strings."))
  if (committedMessages) {
    committedMessages.forEach((message) =>
      assertHexString(message, "The committed messages must be valid hex strings.")
    )
  }

  // cipher check
  assertCipher(cipher)

  // length check
  assertLength(
    publicKey,
    ALGORITHM_CONSTANT.LENGTH_PUBLIC_KEY,
    `The public key must be ${ALGORITHM_CONSTANT.LENGTH_PUBLIC_KEY / 2} bytes long.`,
  )
  assertLength(
    signature,
    ALGORITHM_CONSTANT.LENGTH_SIGNATURE,
    `The signature must be ${ALGORITHM_CONSTANT.LENGTH_SIGNATURE / 2} bytes long.`,
  )

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
export function blindProve(
  publicKey: string,
  signature: string,
  header?: string,
  presentationHeader?: string,
  messages?: Array<string>,
  committedMessages?: Array<string>,
  disclosedIndexes?: Array<number>,
  disclosedCommitmentIndexes?: Array<number>,
  proverBlindness?: string,
  cipher: Cipher = Cipher.XOF_SHAKE_256,
): string {
  // existence check
  assertExist(publicKey, "The public key must be provided.")
  assertExist(signature, "The signature must be provided.")

  // hex string check
  assertHexString(publicKey, "The public key must be a valid hex string.")
  assertHexString(signature, "The signature must be a valid hex string.")
  assertHexString(header, "The header must be a valid hex string.")
  assertHexString(presentationHeader, "The presentation header must be a valid hex string.")
  assertHexString(proverBlindness, "The prover blindness must be a valid hex string.")
  if (messages) messages.forEach((message) => assertHexString(message, "The messages must be valid hex strings."))
  if (committedMessages) {
    committedMessages.forEach((message) =>
      assertHexString(message, "The committed messages must be valid hex strings.")
    )
  }

  // cipher check
  assertCipher(cipher)

  // length check
  assertLength(
    publicKey,
    ALGORITHM_CONSTANT.LENGTH_PUBLIC_KEY,
    `The public key must be ${ALGORITHM_CONSTANT.LENGTH_PUBLIC_KEY / 2} bytes long.`,
  )
  assertLength(
    signature,
    ALGORITHM_CONSTANT.LENGTH_SIGNATURE,
    `The signature must be ${ALGORITHM_CONSTANT.LENGTH_SIGNATURE / 2} bytes long.`,
  )

  // index check
  assertIndexes(
    disclosedIndexes,
    messages?.length,
    "The disclosed indexes must be in ascending order and within bounds.",
  )
  assertIndexes(
    disclosedCommitmentIndexes,
    committedMessages?.length,
    "The disclosed commitment indexes must be in ascending order and within bounds.",
  )

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
export function blindValidate(
  publicKey: string,
  proof: string,
  header?: string,
  presentationHeader?: string,
  l?: number,
  disclosedMessages?: Array<string>,
  disclosedCommitmentMessages?: Array<string>,
  disclosedIndexes?: Array<number>,
  disclosedCommitmentIndexes?: Array<number>,
  cipher: Cipher = Cipher.XOF_SHAKE_256,
): boolean {
  // existence check
  assertExist(publicKey, "The public key must be provided.")
  assertExist(proof, "The proof must be provided.")

  // hex string check
  assertHexString(publicKey, "The public key must be a valid hex string.")
  assertHexString(proof, "The proof must be a valid hex string.")
  assertHexString(header, "The header must be a valid hex string.")
  assertHexString(presentationHeader, "The presentation header must be a valid hex string.")
  if (disclosedMessages) {
    disclosedMessages.forEach((message) =>
      assertHexString(message, "The disclosed messages must be valid hex strings.")
    )
  }
  if (disclosedCommitmentMessages) {
    disclosedCommitmentMessages.forEach((message) =>
      assertHexString(message, "The disclosed commitment messages must be valid hex strings.")
    )
  }

  // cipher check
  assertCipher(cipher)

  // length check
  assertLength(
    publicKey,
    ALGORITHM_CONSTANT.LENGTH_PUBLIC_KEY,
    `The public key must be ${ALGORITHM_CONSTANT.LENGTH_PUBLIC_KEY / 2} bytes long.`,
  )
  assertLengthMin(
    proof,
    ALGORITHM_CONSTANT.LENGTH_MINIMUM_PROOF,
    `The proof must be at least ${ALGORITHM_CONSTANT.LENGTH_MINIMUM_PROOF / 2} bytes long.`,
  )

  // index check
  assertEquality(
    disclosedMessages?.length,
    disclosedIndexes?.length,
    "The length of the disclosed messages and indexes must be equal.",
  )
  assertEquality(
    disclosedCommitmentMessages?.length,
    disclosedCommitmentIndexes?.length,
    "The length of the disclosed commitment messages and indexes must be equal.",
  )

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
