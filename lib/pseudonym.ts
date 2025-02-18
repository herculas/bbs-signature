import {
  blind_messages_with_nym,
  blind_prove_with_nym,
  blind_sign_with_nym,
  blind_validate_with_nym,
  blind_verify_with_nym,
} from "../pkg/bbs_signature.js"

import * as CONSTANT from "./constants.ts"

/**
 * Commit a set of messages that the prover wants to include in the signature, without revealing these messages to the
 * signer. The prover also needs to choose its part of the pseudonym secret `proverNym` as a random scalar value.
 *
 * @param {Array<string>} [committedMessages] A vector of octet strings.
 * @param {string} [proverNym] The prover's part of the pseudonym secret.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {string} A serialized commitment and its proof-of-correctness, along with a secret prover blindness.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-00#name-commitment
 */
export function commit(
  committedMessages?: Array<string>,
  proverNym?: string,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): {
  commitmentWithProof: string
  proverBlindness: string
} {
  const res = blind_messages_with_nym(committedMessages, proverNym, cipher)
  const commitmentWithProof = res.slice(0, -CONSTANT.LENGTH_SCALAR)
  const proverBlindness = res.slice(-CONSTANT.LENGTH_SCALAR)

  return {
    commitmentWithProof,
    proverBlindness,
  }
}

/**
 * Generate a blind BBS signature over an array of messages provided (and committed) by the prover, and a pseudonym
 * secret also chosen by the prover.
 *
 * During the signing process, the signer will provide its own randomness into the pseudonym secret. This will ensure
 * the pseudonym secret always being unique, among different signature generation events.
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
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-00#name-blind-issuance
 */
export function sign(
  secretKey: string,
  publicKey: string,
  commitmentWithProof?: string,
  header?: string,
  messages?: Array<string>,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): {
  signature: string
  entropy: string
} {
  const res = blind_sign_with_nym(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
  const signature = res.slice(0, -CONSTANT.LENGTH_SCALAR)
  const entropy = res.slice(-CONSTANT.LENGTH_SCALAR)
  return { signature, entropy }
}

/**
 * Verify a blind BBS signature with pseudonym, calculating and returning the final pseudonym secret used to calculate
 * the pseudonym value during the proving process.
 *
 * @param {string} publicKey A string representing the public key.
 * @param {string} signature A string representing the signature.
 * @param {string} [header] A string containing context and application specific information.
 * @param {Array<string>} [messages] A vector of strings representing the messages.
 * @param {Array<string>} [committedMessages] A vector of octet strings representing the committed messages.
 * @param {string} [proverNym] A string representing the prover's part of the pseudonym secret.
 * @param {string} [signerNymEntropy] A string representing the signer's part of the pseudonym secret.
 * @param {string} [proverBlindness] A string representing the secret prover blindness.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {boolean} `true` if the signature is valid, `false` otherwise.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-00#name-verification-and-finalizati
 */
export function verify(
  publicKey: string,
  signature: string,
  header?: string,
  messages?: Array<string>,
  committedMessages?: Array<string>,
  proverNym?: string,
  signerNymEntropy?: string,
  proverBlindness?: string,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): string | undefined {
  const res = blind_verify_with_nym(
    publicKey,
    signature,
    header,
    messages,
    committedMessages,
    proverNym,
    signerNymEntropy,
    proverBlindness,
    cipher,
  )
  if (res === "false") {
    return undefined
  } else {
    return res
  }
}

/**
 * Calculate a BBS proof with a pseudonym. The BBS proof is extended to include a zero-knowledge proof-of-correctness of
 * the pseudonym value, i.e., it is correctly calculated using the undisclosed pseudonym secret, and it is "bound" to
 * the underlying BBS signature, i.e., the pseudonym secret is signed by the signer.
 *
 * Validating this proof guarantees authenticity and integrity of the header, the presentation header, and the disclosed
 * messages, the knowledge of a valid BBS signature, as well as the correctness and ownership of the pseudonym secret.
 *
 * @param {string} publicKey A string representing the public key.
 * @param {string} signature A string representing the signature.
 * @param {string} [header] A string containing context and application specific information.
 * @param {string} [presentationHeader] A string containing the presentation header.
 * @param {string} [nymSecret] A string representing the pseudonym secret.
 * @param {string} [contextId] A string representing the context identifier.
 * @param {Array<string>} [messages] A vector of strings representing the messages.
 * @param {Array<string>} [committedMessages] A vector of octet strings representing the committed messages.
 * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
 * @param {Array<number>} [disclosedCommitmentIndexes] Integers representing the indexes of the disclosed commitments.
 * @param {string} [proverBlindness] A string representing the secret prover blindness.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {string} A hex-encoded proof.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-00#name-proof-generation-with-pseud
 */
export function prove(
  publicKey: string,
  signature: string,
  header?: string,
  presentationHeader?: string,
  nymSecret?: string,
  contextId?: string,
  messages?: Array<string>,
  committedMessages?: Array<string>,
  disclosedIndexes?: Array<number>,
  disclosedCommitmentIndexes?: Array<number>,
  proverBlindness?: string,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): {
  proof: string
  pseudonym: string
} {
  const res = blind_prove_with_nym(
    publicKey,
    signature,
    header,
    presentationHeader,
    nymSecret,
    contextId,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const proof = res.slice(0, -CONSTANT.LENGTH_G1_POINT)
  const pseudonym = res.slice(-CONSTANT.LENGTH_G1_POINT)
  return { proof, pseudonym }
}

/**
 * Validate a BBS proof with a pseudonym, given the signer's public key, the proof, the pseudonym, the context
 * identifier that was used to create it, a header and a presentation header, the disclosed messages and committed
 * messages as well as the indexes those messages had in the original vectors of signed messages.
 *
 * Validating this proof will also ensure the correctness and ownership by the prover of the received pseudonym.
 *
 * @param {string} publicKey A string representing the public key.
 * @param {string} proof A string representing the proof.
 * @param {string} [header] A string containing context and application specific information.
 * @param {string} [presentationHeader] A string containing the presentation header.
 * @param {string} [pseudonym] A string representing the pseudonym.
 * @param {string} [contextId] A string representing the context identifier.
 * @param {number} [l] The total number of signer known messages. If not specified, it defaults to 0.
 * @param {Array<string>} [disclosedMessages] A vector of strings representing the disclosed messages.
 * @param {Array<string>} [disclosedCommitmentMessages] Strings representing the disclosed commitment messages.
 * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
 * @param {Array<number>} [disclosedCommitmentIndexes] Integers representing the indexes of the disclosed commitments.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {boolean} `true` if the proof is valid, `false` otherwise.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-00#name-proof-verification-with-pse
 */
export function validate(
  publicKey: string,
  proof: string,
  header?: string,
  presentationHeader?: string,
  pseudonym?: string,
  contextId?: string,
  l?: number,
  disclosedMessages?: Array<string>,
  disclosedCommitmentMessages?: Array<string>,
  disclosedIndexes?: Array<number>,
  disclosedCommitmentIndexes?: Array<number>,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): boolean {
  return blind_validate_with_nym(
    publicKey,
    proof,
    header,
    presentationHeader,
    pseudonym,
    contextId,
    l,
    disclosedMessages,
    disclosedCommitmentMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )
}
