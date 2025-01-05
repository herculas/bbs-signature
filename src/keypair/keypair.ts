import { Cipher } from "../suite/cipher.ts"
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
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-secret-key
 */
export function generateSecretKey(
  material: Uint8Array,
  info: Uint8Array = new Uint8Array(),
  dst: Uint8Array,
  cipher: Cipher,
): bigint {
  /**
   * Procedure:
   * 
   * 1. If len(key_material) < 32, return INVALID.
   * 2. If len(key_info) > 65535, return INVALID.
   * 3. derive_input := key_material || I2OSP(len(key_info), 2) || key_info.
   * 4. SK := hash_to_scalar(derive_input, key_dst).
   * 5. If SK is INVALID, return INVALID.
   * 6. Return SK.
   */
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
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-public-key
 */
export function generatePublicKey(secretKey: bigint, cipher: Cipher): Uint8Array {
  /**
   * Procedure:
   * 
   * 1. W := SK * BP2.
   * 2. Return point_to_octets_E2(W).
   */
  const w = cipher.types.G2.BASE.multiply(secretKey)
  return w.toRawBytes()
}
