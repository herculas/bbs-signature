import {
  derive_public_key,
  generate_secret_key,
  prove as core_prove,
  sign as core_sign,
  validate as core_validate,
  verify as core_verify,
} from "../pkg/bbs_signature.js"

type Cipher = "BLS12_381_G1_XOF_SHAKE_256" | "BLS12_381_G1_XMD_SHA_256"

/**
 * Generate a secret key deterministically from a secret material and an optional key information string.
 *
 * @param {string} material A secret string from which to generate the secret key, at least 32 bytes.
 * @param {string} [info] A context-specific information to bind the secret key to a particular context.
 * @param {string} dst A string representing the domain separation tag.
 * @param {Cipher} cipher The cipher suite.
 *
 * @returns {string} A hex-encoded uniformly random integer in the range [1, r - 1].
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-secret-key
 */
export function generateSecretKey(material: string, info: string | undefined, dst: string, cipher: Cipher): string {
  return generate_secret_key(material, info, dst, cipher)
}

/**
 * Generate a public key corresponding to the given private key.
 *
 * @param {string} secretKey The private key.
 *
 * @returns {string} The hex-encoded public key.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-public-key
 */
export function derivePublicKey(secretKey: string): string {
  return derive_public_key(secretKey)
}

/**
 * Generate a keypair deterministically from a secret key material string.
 * 
 * @param {string} material A secret string from which to generate the secret key, at least 32 bytes.
 * @param {string} [info] A context-specific information to bind the secret key to a particular context.
 * @param {string} dst A string representing the domain separation tag.
 * @param {Cipher} cipher The cipher suite.
 * 
 * @returns {secretKey: string, publicKey: string} An object containing the secret key and the public key.
 */
export function generateKeypair(
  material: string,
  info: string | undefined,
  dst: string,
  cipher: Cipher,
): { secretKey: string; publicKey: string } {
  const secretKey = generateSecretKey(material, info, dst, cipher)
  const publicKey = derivePublicKey(secretKey)
  return { secretKey, publicKey }
}

/**
 * Generate a BBS Signature from a secret key, over a header and a set of messages.
 *
 * @param {string} secretKey A string representing the secret key.
 * @param {string} publicKey A string representing the public key.
 * @param {string} [header] A string containing context and application specific information.
 * @param {Array<string>} [messages] A vector of hex-encoded strings representing the messages.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {string} A signature encoded as a string.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-signature-generation-sign
 */
export function sign(
  secretKey: string,
  publicKey: string,
  header: string | undefined,
  messages: Array<string> | undefined,
  cipher: Cipher,
): string {
  return core_sign(secretKey, publicKey, header, messages, cipher)
}

/**
 * Validate a BBS Signature, given a public key, a header, and a set of messages.
 *
 * @param {string} publicKey A string representing the public key.
 * @param {string} signature A string representing the signature.
 * @param {string} [header] A string containing context and application specific information.
 * @param {Array<string>} [messages] A vector of strings representing the messages.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {boolean} `true` if the signature is valid, `false` otherwise.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-signature-verification-veri
 */
export function verify(
  publicKey: string,
  signature: string,
  header: string | undefined,
  messages: Array<string> | undefined,
  cipher: Cipher,
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
 * @param {string} publicKey A string representing the public key.
 * @param {string} signature A string representing the signature.
 * @param {string} [header] A string containing context and application specific information.
 * @param {string} [presentationHeader] A string containing the presentation header.
 * @param {Array<string>} [messages] A vector of strings representing the messages.
 * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {string} A hex-encoded proof.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-proof-generation-proofgen
 */
export function prove(
  publicKey: string,
  signature: string,
  header: string | undefined,
  presentationHeader: string | undefined,
  messages: Array<string> | undefined,
  disclosedIndexes: Array<number> | undefined,
  cipher: Cipher,
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
 * @param {string} publicKey A string representing the public key.
 * @param {string} proof A string representing the proof.
 * @param {string} [header] A string containing context and application specific information.
 * @param {string} [presentationHeader] A string containing the presentation header.
 * @param {Array<string>} [disclosedMessages] A vector of strings representing the disclosed messages.
 * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {boolean} `true` if the proof is valid, `false` otherwise.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-proof-verification-proofver
 */
export function validate(
  publicKey: string,
  proof: string,
  header: string | undefined,
  presentationHeader: string | undefined,
  disclosedMessages: Array<string> | undefined,
  disclosedIndexes: Array<number> | undefined,
  cipher: Cipher,
): boolean {
  return core_validate(publicKey, proof, header, presentationHeader, disclosedMessages, disclosedIndexes, cipher)
}
