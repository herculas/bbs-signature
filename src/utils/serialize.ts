import { Cipher } from "../types/cipher.ts"
import { type G1Projective, type G2Projective, isE1Point, isE2Point, Scalar } from "../types/elements.ts"
import { concatenate, i2osp } from "./format.ts"

/**
 * Transform multiple elements of different types (i.e., elements that are not yet in octet string format) into a single
 * octet string. The resulting output can be used as an input to a hash function, or to serialize a signature ort proof.
 *
 * @param {Array} array An array of elements to be serialized. Each element MUST be either a point of G1 or G2, a
 * scalar, an ASCII string, or an integer value between 0 and 2^64-1.
 *
 * @returns {Uint8Array} The octet string representation of the inputted elements.
 *
 * @see https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#section-4.2.4.1
 */
export function serialize(
  array: Array<G1Projective | G2Projective | Scalar | Uint8Array | number>,
  cipher: Cipher,
): Uint8Array {
  /**
   * Parameters:
   *
   * - octet_scalar_length: a non-negative integer. The length of a scalar octet representation, defined by the
   *   ciphersuite.
   * - r: the prime order of the subgroups G1 and G2, defined by the ciphersuite.
   * - point_to_octets_E1 and point_to_octets_E2: operations that serialize a point in E1 or E2 to an octet string of
   *   fixed length, defined by the ciphersuite.
   */
  const octetScalarLength = cipher.octetScalarLength

  /**
   * Procedure:
   *
   * 1. let octet_result be an empty octet string.
   * 2. for element in input_array:
   * 3.     if element is a point in G1: element_octets = point_to_octets_E1(element)
   * 4.     else if element is a point in G2: element_octets = point_to_octets_E2(element)
   * 5.     else if element is a scalar: element_octets = i2osp(element, octet_scalar_length)
   * 6.     else if element is an integer: element_octets = i2osp(element, 8)
   * 7.     else: return INVALID
   * 8.     octet_result = octet_result || element_octets
   * 9. return octet_result
   */
  const octetResult = new Array(array.length)
  for (const element of array) {
    if (isE1Point(element)) {
      octetResult.push(element.toRawBytes())
    } else if (isE2Point(element)) {
      octetResult.push(element.toRawBytes())
    } else if (typeof element === "bigint") {
      octetResult.push(i2osp(element, octetScalarLength))
    } else if (element instanceof Uint8Array) {
      octetResult.push(element)
    } else if (typeof element === "number") {
      octetResult.push(i2osp(BigInt(element), 8))
    } else {
      throw new Error("invalid element type")
    }
  }
  return concatenate(...octetResult)
}

/**
 * Encode a signature to an octet string.
 *
 * @param {[G1Projective, Scalar]} signature A valid signature in the form (A, e), where A is a point in G1, and e is a 
 * non-zero scalar modulo r.
 * @param {Cipher} cipher The ciphersuite to use.
 *
 * @returns {Uint8Array} The octet string representation of the inputted signature.
 *
 * @see https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-to-octets
 */
export function signatureToOctets(signature: [G1Projective, Scalar], cipher: Cipher): Uint8Array {
  /**
   * Procedure:
   *
   * 1. (A, e) = signature
   * 2. return serialize((A, e))
   */
  return serialize(signature, cipher)
}
