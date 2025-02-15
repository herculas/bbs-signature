import { derive_public_key, generate_secret_key } from "../../pkg/bbs_signature.js"

import { assertCipher, assertExist, assertHexString, assertLength, assertLengthMin } from "../util/assertion.ts"
import { Cipher } from "../constant/cipher.ts"

import * as ALGORITHM_CONSTANT from "../constant/algorithm.ts"

/**
 * Generate a secret key deterministically from a secret material and an optional key information string.
 *
 * @param {string} material A secret string from which to generate the secret key, at least 32 bytes.
 * @param {string} [info] A context-specific information to bind the secret key to a particular context.
 * @param {string} [dst] A string representing the domain separation tag.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {string} A hex-encoded uniformly random integer in the range [1, r - 1].
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-secret-key
 */
export function generateSecretKey(
  material: string,
  info?: string,
  dst?: string,
  cipher: Cipher = Cipher.XOF_SHAKE_256,
): string {
  // existence check
  assertExist(material, "The secret material must be provided.")

  // hex string check
  assertHexString(material, "The secret material must be a valid hex string.")
  assertHexString(info, "The info must be a valid hex string.")
  assertHexString(dst, "The domain separation tag must be a valid hex string.")

  // cipher check
  assertCipher(cipher)

  // length check
  assertLengthMin(
    material,
    ALGORITHM_CONSTANT.LENGTH_MINIMUM_KEY_MATERIAL,
    `The secret material must be at least ${ALGORITHM_CONSTANT.LENGTH_MINIMUM_KEY_MATERIAL / 2} bytes.`,
  )

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
  // existence check
  assertExist(secretKey, "The secret key must be provided.")

  // hex string check
  assertHexString(secretKey, "The secret key must be a valid hex string.")

  // length check
  assertLength(
    secretKey,
    ALGORITHM_CONSTANT.LENGTH_SECRET_KEY,
    `The secret key must be ${ALGORITHM_CONSTANT.LENGTH_SECRET_KEY / 2} bytes.`,
  )
  return derive_public_key(secretKey)
}

/**
 * Generate a keypair deterministically from a secret key material string.
 *
 * @param {string} material A secret string from which to generate the secret key, at least 32 bytes.
 * @param {string} [info] A context-specific information to bind the secret key to a particular context.
 * @param {string} [dst] A string representing the domain separation tag.
 * @param {Cipher} [cipher] The cipher suite. If not specified, it defaults to `BLS12_381_G1_XOF_SHAKE_256`.
 *
 * @returns {secretKey: string, publicKey: string} An object containing the secret key and the public key.
 */
export function generateKeypair(
  material: string,
  info?: string,
  dst?: string,
  cipher: Cipher = Cipher.XOF_SHAKE_256,
): { secretKey: string; publicKey: string } {
  const secretKey = generateSecretKey(material, info, dst, cipher)
  const publicKey = derivePublicKey(secretKey)
  return { secretKey, publicKey }
}
