import { Cipher } from "../suite/cipher.ts"
import { G1Projective } from "../suite/elements.ts"
import { concatenate, i2osp } from "./format.ts"
import { hashToScalar } from "./hash.ts"
import { serialize } from "./serialize.ts"

/**
 * Calculate the domain value, a scalar representing the distillation of all essential contextual information for a
 * signature. The same domain value must be calculated by all parties (the signer, the prover and the verifier) for both
 * the signature and the proofs to be validated.
 *
 * The input to the domain value includes a `header` property chosen by the signer to encode any information that is
 * required to be revealed by the prover (such as an expiration date, or an identifier for the target audience). This is
 * in contrast to the signed message values, which may be withheld during a proof.
 *
 * When a signature is generated, the domain value is combined with a specific generator point `q1` to protect the
 * integrity of the public parameters and the header.
 *
 * @param {Uint8Array} publicKey An octet string representing the public key of the signer.
 * @param {G1Projective} q1 The first generator point.
 * @param {Array<G1Projective>} hPoints The set of generator points.
 * @param {Uint8Array} [header] The header octet string. If not specified, it defaults to an empty array.
 * @param {Uint8Array} [apiId] The interface identifier. If not specified, it defaults to an empty array.
 * @param {Cipher} cipher The cipher suite.
 *
 * @returns {bigint} The domain value.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-domain-calculation
 */
export function calculateDomain(
  publicKey: Uint8Array,
  q1: G1Projective,
  hPoints: Array<G1Projective>,
  header: Uint8Array = new Uint8Array(),
  apiId: Uint8Array = new Uint8Array(),
  cipher: Cipher,
): bigint {
  /**
   * Definitions:
   *
   * 1. hash_to_scalar_dst: an octet string representing the domain separation tag: <api_id> || "H2S_".
   */
  const hashToScalarDst = concatenate(apiId, new TextEncoder().encode("H2S_"))

  /**
   * Deserialization:
   *
   * 1. L := len(h_points).
   * 2. (H_1, H_2, ..., H_L) := h_points.
   */
  const len = hPoints.length

  /**
   * ABORT if:
   *
   * 1. len(header) > 2^64 - 1 or L > 2^64 - 1.
   */
  if (header.length > 2n ** 64n - 1n || len > 2n ** 64n - 1n) {
    throw new Error("Header or hPoints are too long")
  }

  /**
   * Procedure:
   *
   * 1. dom_array := (L, Q_1, H_1, H_2, ..., H_L).
   * 2. dom_octets := serialize(dom_array) || api_id.
   * 3. dom_input := PK || dom_octets || i2osp(len(header), 8) || header.
   * 4. Return hash_to_scalar(dom_input, hash_to_scalar_dst).
   */
  const domArray = [len, q1, ...hPoints]
  const domOctets = concatenate(serialize(domArray, cipher), apiId)
  const domInput = concatenate(publicKey, domOctets, i2osp(BigInt(header.length), 8), header)
  return hashToScalar(domInput, hashToScalarDst, cipher)
}
