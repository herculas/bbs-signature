import { Cipher } from "../suite/cipher.ts"
import { G1Projective } from "../suite/elements.ts"
import { concatenate, i2osp } from "./format.ts"
import { hashToScalar } from "./hash.ts"

/**
 * Create a set of randomly sampled points from the G1 group, called the generators. 
 * 
 * This operation makes use of the `expand_message` and `hash_to_curve` primitives to hash a seed to a set of 
 * generators. These primitives are implicitly defined by the cipher suite.
 *
 * @param {number} count Number of generators to create.
 * @param {Uint8Array} [apiId] The interface identifier. If not specified, it defaults to an empty array.
 * @param {Cipher} cipher The cipher suite.
 *
 * @returns {Array<G1Projective>} An array of generators.
 * 
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-generators-calculation
 */
export function createGenerators(
  count: number,
  apiId: Uint8Array = new Uint8Array(),
  cipher: Cipher,
): Array<G1Projective> {
  /**
   * Definitions:
   *
   * - seed_dst: an octet string representing the domain separation tag: api_id || "SIG_GENERATOR_SEED_".
   * - generator_dst: an octet string representing the domain separation tag: api_id || "SIG_GENERATOR_DST_".
   * - generator_seed: an octet string representing the domain separation tag: api_id || "MESSAGE_GENERATOR_SEED".
   */
  const seedDst = concatenate(apiId, new TextEncoder().encode("SIG_GENERATOR_SEED_"))
  const generatorDst = concatenate(apiId, new TextEncoder().encode("SIG_GENERATOR_DST_"))
  const generatorSeed = concatenate(apiId, new TextEncoder().encode("MESSAGE_GENERATOR_SEED"))

  /**
   * Procedure:
   *
   * 1. v := expand_message(generator_seed, seed_dst, expand_len).
   * 2. For i in (1, 2, ..., count):
   * 3.     v := expand_message(v || i2osp(i, 8), seed_dst, expand_len).
   * 4.     generators_i := hash_to_curve_g1(v, generator_dst).
   * 5. Return (generators_1, generators_2, ..., generators_count).
   */
  const generators = new Array<G1Projective>(count)
  let v = cipher.expandMessage(generatorSeed, seedDst)
  for (let i = 1; i <= count; i++) {
    v = cipher.expandMessage(concatenate(v, i2osp(BigInt(i), 8)), seedDst)
    generators[i - 1] = cipher.hashToCurveG1(v, generatorDst)
  }
  return generators
}

/**
 * Map a list of messages to their respective scalar values.
 *
 * @param {Array<Uint8Array>} messages The messages, a vector of octet strings.
 * @param {Uint8Array} apiId The interface identifier. If not specified, it defaults to an empty array.
 * @param {Cipher} cipher The cipher suite.
 *
 * @returns {Array<bigint>} The scalar values.
 * 
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-messages-to-scalars
 */
export function messagesToScalars(
  messages: Array<Uint8Array>,
  apiId: Uint8Array = new Uint8Array(),
  cipher: Cipher,
): Array<bigint> {
  /**
   * Definitions:
   *
   * 1. map_dst: an octet string representing the domain separation tag: api_id || "MAP_MSG_TO_SCALAR_AS_HASH_".
   */
  const mapDst = concatenate(apiId, new TextEncoder().encode("MAP_MSG_TO_SCALAR_AS_HASH_"))

  /**
   * ABORT if:
   *
   * 1. len(messages) > 2^64 - 1.
   */
  if (!Number.isSafeInteger(messages.length)) {
    throw new Error(`messagesToScalars: too many messages`)
  }

  /**
   * Procedure:
   *
   * 1. L := len(messages).
   * 2. For i in (1, 2, ..., L):
   * 3.     msg_scalar_i := hash_to_scalar(messages[i], map_dst).
   * 4. Return (msg_scalar_1, msg_scalar_2, ..., msg_scalar_L).
   */
  return messages.map((message) => hashToScalar(message, mapDst, cipher))
}
