import { mod } from "@noble/curves/abstract/modular"
import { randomBytes } from "@noble/hashes/utils"

import { os2ip } from "./format.ts"
import { Cipher } from "../suite/cipher.ts"

/**
 * Sample the requested number of pseudo-random scalars.
 *
 * @param {number} count The number of scalars to return.
 * @param {Cipher} cipher The cipher suite to use.
 *
 * @returns {Array<bigint>} The requested number of pseudo-random scalars.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-random-scalars
 */
export function randomScalars(count: number, cipher: Cipher): Array<bigint> {
  /**
   * Procedure:
   *
   * 1. For i in (1, 2, ..., count):
   * 2.     scalar_i := os2ip(get_random(expand_len)) mod r.
   * 3. Return (scalar_1, scalar_2, ..., scalar_count).
   */
  return Array.from({ length: count }, () => {
    return mod(
      os2ip(randomBytes(cipher.expandLength)),
      cipher.types.Fr.ORDER,
    )
  })
}

/**
 * Deterministically calculate `count` random-looking scalars from a single `seed`, given a domain separation tag `dst`.
 *
 * @param {Uint8Array} seed The seed to use.
 * @param {Uint8Array} dst The domain separation tag to use.
 * @param {number} count The number of scalars to return.
 * @param {Cipher} cipher The cipher suite to use.
 *
 * @returns {Array<bigint>} The requested number of pseudo-random scalars.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-mocked-random-scalars
 */
export function seededRandomScalars(seed: Uint8Array, dst: Uint8Array, count: number, cipher: Cipher): Array<bigint> {
  /**
   * ABORT if:
   *
   * 1. count * expand_len > 65535.
   */
  if (cipher.expandLength * count > 65535) {
    throw new Error("count * expand_len > 65535")
  }

  /**
   * Procedure:
   *
   * 1. out_len := expand_len * count.
   * 2. v := expand_message(seed, dst, out_len).
   * 3. If v is INVALID, return INVALID.
   *
   * 4. For i in (1, 2, ..., count):
   * 5.     start_idx := (i - 1) * expand_len.
   * 6.     end_idx := i * expand_len - 1.
   * 7.     r_i := os2ip(v[start_idx..end_idx]) mod r.
   * 8. Return (r_1, r_2, ..., r_count).
   */
  const outLength = cipher.expandLength * count
  const v = cipher.expandMessage(seed, dst, outLength)

  return Array.from({ length: count }, (_, i) => {
    const startIdx = i * cipher.expandLength
    const endIdx = (i + 1) * cipher.expandLength
    return mod(
      os2ip(v.subarray(startIdx, endIdx)),
      cipher.types.Fr.ORDER,
    )
  })
}
