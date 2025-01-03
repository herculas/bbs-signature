import { Cipher } from "../types/cipher.ts"
import { concatenate, i2osp } from "../utils/format.ts"
import { hashToScalar } from "../utils/hash.ts"

/**
 * Generate a secret key deterministically from a secret octet string.
 *
 * @param {Uint8Array} material A secret octet string from which to generate the secret key, at least 32 bytes.
 * @param {Uint8Array} info An context-specific information to bind the secret key to a particular context. If not
 * specified, it is set to an empty string.
 * @param {Uint8Array} dst An octet string representing the domain separation tag. If not specified, it is set to
 * `ciphersuite_id || KEYGEN_DST_`.
 * @param {Cipher} cipher The cipher suite to use.
 *
 * @returns {bigint} A uniformly random integer in the range [1, r - 1].
 *
 * @see https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-secret-key
 */
export function generateSecretKey(
  material: Uint8Array,
  info: Uint8Array = new Uint8Array(),
  dst: Uint8Array,
  cipher: Cipher,
): bigint {
  if (material.length < 32) {
    throw new Error("material must be at least 32 bytes")
  }
  if (info.length > 65535) {
    throw new Error("info must be at most 65535 bytes")
  }

  const derivedInput = concatenate(material, i2osp(BigInt(info.length), 2), info)
  return hashToScalar(derivedInput, dst, cipher)
}

/**
 * Generate a public key corresponding to the given private key.
 *
 * @param {bigint} secretKey The private key.
 * @param {Cipher} cipher The cipher suite to use.
 *
 * @returns {Uint8Array} The public key in octet format.
 *
 * @see https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-public-key
 */
export function generatePublicKey(secretKey: bigint, cipher: Cipher): Uint8Array {
  const w = cipher.types.G2.BASE.multiply(secretKey)
  return w.toRawBytes()
}
