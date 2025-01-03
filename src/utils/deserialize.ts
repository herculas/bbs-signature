import { Cipher } from "../types/cipher.ts"
import { G1Projective, G2Projective, Scalar } from "../types/elements.ts"
import { os2ip } from "./format.ts"

/**
 * Decode an octet string, validate it, and return the underlying components that make up the signature.
 *
 * @param {Uint8Array} octets The octet string representation of a signature.
 * @param {Cipher} cipher The ciphersuite to use.
 *
 * @returns {[G1Projective, Fr]} The signature components (A, e) where A is a point in G1, and e is a non-zero scalar modulo r.
 *
 * @see https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-octets-to-signature
 */
export function octetsToSignature(octets: Uint8Array, cipher: Cipher): [G1Projective, Scalar] {
  /**
   * Parameters:
   *
   * - octets_to_point_E1: operation that deserializes an octet string to a point in G1, defined by the ciphersuite.
   * - subgroup_check_G1: operation that checks if a point is in the subgroup G1.
   */
  const order = cipher.types.Fr.ORDER

  /**
   * Procedure:
   *
   * 1. expected_len = octet_point_length + octet_scalar_length
   * 2. if len(signature_octets) != expected_len: return INVALID
   * 3. A_octets = signature_octets[0..(octet_point_length - 1)]
   * 4. A = octets_to_point_E1(A_octets)
   * 5. If A is INVALID, return INVALID
   * 6. If A == Identity_G1, return INVALID
   * 7. If subgroup_check_G1(A) == false, return INVALID
   *
   * 8. index = octet_point_length
   * 9. end_index = index + octet_scalar_length - 1
   * 10. e = os2ip(signature_octets[index..end_index])
   * 11. If e == 0 or e >= r, return INVALID
   * 12. return (A, e)
   */
  const expectedLength = cipher.octetPointLength + cipher.octetScalarLength
  if (octets.length !== expectedLength) {
    throw new Error("invalid signature length")
  }

  const aOctets = octets.subarray(0, cipher.octetPointLength)
  const a = cipher.types.G1.fromHex(aOctets)
  if (a.equals(cipher.types.G1.ZERO)) {
    throw new Error("invalid signature point")
  }

  const e = os2ip(octets.subarray(cipher.octetPointLength))
  if (e < 0n || e >= order) {
    throw new Error("invalid signature scalar")
  }

  return [a, e]
}

/**
 * Decode an octet string representing a proof, validate it, and return the underlying components that make up the
 * proof value.
 *
 * The proof value outputted by this operation consists of the following components, in that order:
 *     1. Three valid points of G1, each of which MUST not equal to the identity point.
 *     2. Three integers representing scalars in the range of [1, r-1].
 *     3. A set of integers representing scalars in the range of [1, r-1], corresponding to the undisclosed from the
 *        proof message commitments. This set can be empty.
 *     4. One integer representing a scalar in the range of [1, r-1], corresponding to the proof's challenge.
 *
 * @param {Uint8Array} octets The octet string representation of a proof.
 * @param {Cipher} cipher The ciphersuite to use.
 *
 * @returns
 *
 * @see https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-octets-to-proof
 */
export function octetsToProof(
  octets: Uint8Array,
  cipher: Cipher,
): [G1Projective, G1Projective, G1Projective, Scalar, Scalar, Scalar, Array<Scalar>, Scalar] {
  /**
   * Parameters:
   *
   * - r: a non-negative integer. The prime order of the G1 and G2 groups, defined by the ciphersuite.
   * - octet_point_length: a non-negative integer. The length of an octet string representing a point in G1.
   * - octet_scalar_length: a non-negative integer. The length of an octet string representing a scalar.
   */
  const r = cipher.types.Fr.ORDER
  const octetPointLength = cipher.octetPointLength
  const octetScalarLength = cipher.octetScalarLength

  /**
   * Procedure:
   *
   * 1. proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length
   * 2. if len(proof_octets) < proof_len_floor: return INVALID
   *
   * 3. index = 0
   * 4. for i in (0, 2):
   * 5.     end_index = index + octet_point_length - 1
   * 6.     A_i = octets_to_point_E1(proof_octets[index..end_index])
   * 7.     If A_i is INVALID or A_i == Identity_G1, return INVALID
   * 8.     If subgroup_check_G1(A_i) == false, return INVALID
   * 9.     index += octet_point_length
   *
   * 10. j = 0
   * 11. while index < len(proof_octets):
   * 12.     end_index = index + octet_scalar_length - 1
   * 13.     s_j = os2ip(proof_octets[index..end_index])
   * 14.     If s_j == 0 or s_j >= r, return INVALID
   * 15.     index += octet_scalar_length
   * 16.     j += 1
   *
   * 17. If index != len(proof_octets): return INVALID
   * 18. msg_commitments = []
   * 19. If j > 4, set msg_commitments = [s_3, s_4, ..., s_{j-2}]
   *
   * 20. return (A_0, A_1, A_2, s_0, s_1, s_2, msg_commitments, s_{j-1})
   */
  const proofLenFloor = 3 * octetPointLength + 4 * octetScalarLength
  if (octets.length < proofLenFloor) {
    throw new Error("invalid proof length")
  }
  const remainder = octets.length - proofLenFloor
  if (remainder % octetScalarLength !== 0) {
    throw new Error("invalid proof length")
  }

  let index = 0
  const a = new Array<G1Projective>(3)
  for (let i = 0; i <= 2; ++i) {
    a[i] = cipher.types.G1.fromHex(octets.subarray(index, index + octetPointLength))
    if (a[i].equals(cipher.types.G1.ZERO)) {
      throw new Error("invalid proof point")
    }
    index += octetPointLength
  }

  const s = []
  while (index < octets.length) {
    const s_j = os2ip(octets.subarray(index, index + octetScalarLength))
    if (s_j === 0n || s_j >= r) {
      throw new Error("invalid proof scalar")
    }
    s.push(s_j)
    index += octetScalarLength
  }

  if (index !== octets.length) {
    throw new Error("invalid proof length")
  }

  const msgCommitments = []
  if (s.length > 4) {
    msgCommitments.push(...s.slice(3, s.length - 1))
  }

  return [a[0], a[1], a[2], s[0], s[1], s[2], msgCommitments, s[s.length - 1]]
}

/**
 * Decode an octet string representing a public key, validate it, and return the corresponding point in G2.
 *
 * @param {Uint8Array} octets The octet string representation of a public key.
 * @param {Cipher} cipher The ciphersuite to use.
 *
 * @returns {G2Projective} The public key as a point in G2.
 *
 * @see https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-octets-to-public-key
 */
export function octetsToPublicKey(octets: Uint8Array, cipher: Cipher): G2Projective {
  /**
   * Procedure:
   *
   * 1. W = octets_to_point_E2(public_key_octets)
   * 2. if W is INVALID or W == Identity_G2: return INVALID
   * 3. If subgroup_check_G2(W) == false: return INVALID
   * 4. return W
   */
  const w = cipher.types.G2.fromHex(octets)
  if (w.equals(cipher.types.G2.ZERO)) {
    throw new Error("invalid public key")
  }
  return w
}
