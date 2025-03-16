/**
 * BBS key generation and derivation.
 * @module key
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07
 */

import { derive_public_key, generate_secret_key } from "../pkg/bbs_signature.js"

import * as CONSTANT from "./constants.ts"

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
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-08#name-secret-key
 */
export function generateSecret(
  material: string,
  info?: string,
  dst?: string,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): string {
  return generate_secret_key(material, info, dst, cipher)
}

/**
 * Generate a public key corresponding to the given private key.
 *
 * @param {string} secretKey The private key.
 *
 * @returns {string} The hex-encoded public key.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-08#name-public-key
 */
export function derivePublic(secretKey: string): string {
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
export function createPair(
  material: string,
  info?: string,
  dst?: string,
  cipher: CONSTANT.Cipher = CONSTANT.Cipher.XOF_SHAKE_256,
): { secretKey: string; publicKey: string } {
  const secretKey = generateSecret(material, info, dst, cipher)
  const publicKey = derivePublic(secretKey)
  return { secretKey, publicKey }
}
