import { Fpt, Fr, G1, G1Projective, G2, G2Projective, Gt } from "./elements.ts"

/**
 * The `Cipher` interface represents a ciphersuite, which is a set of cryptographic algorithms used to implement a
 * specific signature scheme. This interface defines terms specific to a pairing-friendly elliptic curve.
 */
export interface Cipher {
  /**
   * The unique identifier for the ciphersuite, which will be represented as an ASCII encoded octet string.
   *
   * The REQUIRED format for this string is `BBS_ || H2C_SUITE_ID || ADD_INFO`, where:
   *  - `H2C_SUITE_ID` is the identifier of the hash-to-curve suite used by the ciphersuite, and
   *  - `ADD_INFO` is an optional additional octet string indicating any additional information used to uniquely qualify
   *    the ciphersuite. When specified, this value MUST only contain ASCII encoded characters with codes between 0x21
   *    and 0x7E, inclusive, and MUST end with an underscore.
   */
  id: Uint8Array

  /**
   * The cryptographic hash function used by the ciphersuite.
   */
  hash: string

  /**
   * Number of bytes to represent a scalar value, in the multiplicative group of integers mod r, encoded as an octet
   * string.
   *
   * It is RECOMMENDED that this value be set to `ceil(log2(r)/8)`.
   */
  octetScalarLength: number

  /**
   * Number of bytes to represent a point, encoded as an octet string.
   */
  octetPointLength: number

  /**
   * The operation used to expand a message to a scalar value.
   *
   * This value MUST be defined to be at least `ceil(log2(r)+k/8)`, where `r` and `k` are defined by the ciphersuite.
   */
  expandLength: number

  /**
   * A fixed point in the G1 group, different from the base point `bp1`.
   *
   * This leaves the base point `bp1` free for use in other protocols, like key commitment and proof of possession.
   */
  p1: G1Projective

  /**
   * The fields and groups of the ciphersuite.
   */
  types: {
    G1: G1
    G2: G2
    Fr: Fr
    Fpt: Fpt
  }

  /**
   * A cryptographic hash function that takes an arbitrary octet string as input, and returns a point in G1.
   *
   * @param {Uint8Array} message An octet string representing the message to be hashed.
   * @param {Uint8Array} dst The domain separation tag.
   *
   * @returns {G1Projective} A point in G1.
   */
  hashToCurveG1(message: Uint8Array, dst: Uint8Array): G1Projective

  /**
   * The operation used to expand a message to a scalar value.
   *
   * @param {Uint8Array} message An octet string representing the message to be expanded.
   * @param {Uint8Array} dst The domain separation tag.
   * @param {number} expandLength The number of bytes to expand the message to.
   *
   * @returns {Uint8Array} An octet string representing the expanded message.
   */
  expandMessage(message: Uint8Array, dst: Uint8Array, expandLength?: number): Uint8Array

  /**
   * The non-degenerate bilinear pairing operation, mapping a point in G1 and and a point in G2 to a point in Gt.
   *
   * @param {G1Projective} point1 A point in G1.
   * @param {G2Projective} point2 A point in G2.
   *
   * @returns {Gt} The result of the pairing operation.
   */
  pairing(point1: G1Projective, point2: G2Projective): Gt

  /**
   * Compare two pairings for equality.
   *
   * @param {Gt} pair1 The first pairing to compare.
   * @param {Gt} pair2 The second pairing to compare.
   * @param {Gt} pair3 The third pairing to compare.
   */
  pairingCompare(pair1: Gt, pair2: Gt, pair3: Gt): boolean
}
