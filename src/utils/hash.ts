import { mod } from "@noble/curves/abstract/modular"

import { Cipher } from "../types/cipher.ts"
import { os2ip } from "./format.ts"

/**
 * Hash an arbitrary octet string to a scalar value in the multiplicative group of integers mod `r`.
 *
 * @param {Uint8Array} message An octet string representing the message to be hashed.
 * @param {Uint8Array} dst The domain separation tag.
 * @param {Cipher} cipher The ciphersuite.
 *
 * @returns {bigint} The hash value as a scalar.
 * 
 * @see https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-hash-to-scalar
 */
export function hashToScalar(message: Uint8Array, dst: Uint8Array, cipher: Cipher): bigint {
  /**
   * ABORT if:
   *
   * 1. len(dst) > 255.
   */
  if (dst.length > 255) {
    throw new Error(`hashToScalar: dst too long`)
  }

  /**
   * Procedure:
   *
   * 1. uniform_bytes = expand_message(msg_octets, dst, expand_len)
   * 2. return os2ip(uniform_bytes) mod r
   */
  const bytes = cipher.expandMessage(message, dst)
  return mod(os2ip(bytes), cipher.types.Fr.ORDER)
}
