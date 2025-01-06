import { Cipher } from "../suite/cipher.ts"
import { G1Projective, Scalar } from "../suite/elements.ts"
import { calculateDomain } from "../utils/domain.ts"
import { concatenate, i2osp } from "../utils/format.ts"
import { hashToScalar } from "../utils/hash.ts"
import { proofToOctets, serialize } from "../utils/serialize.ts"

/**
 * Initialize the proof and returns one of the inputs passed to the challenge calculation operation. The input
 * `messages` MUST be supplied in the same order as they were supplied to the sign function.
 *
 * The prover need to provide the messages which are not to be disclosed. For this purpose, along with the list of
 * signed messages, this operation also accepts a set of integers in the range [0, L - 1], where L is the number of the
 * vector of messages, in ascending order, representing the indexes of the undisclosed messages.
 *
 * To blind the inputted `signature` and the undisclosed messages, this operation also accepts a set of uniformly
 * sampled random scalars. This set must have exactly 5 more items than the list of undisclosed indexes.
 *
 * @param {Uint8Array} publicKey An octet string representing the public key.
 * @param {[G1Projective, Scalar]} signature A vector containing a G1 point and a scalar representing the signature.
 * @param {Array<G1Projective>} generators A vector of pseudo-random points in G1.
 * @param {Array<Scalar>} randomScalars A vector of uniformly sampled random scalars.
 * @param {Uint8Array} [header] An octet string containing context and application specific information.
 * @param {Array<Scalar>} [messages] A vector of scalars representing the messages.
 * @param {Array<number>} [undisclosedIndexes] A vector representing the indexes of the undisclosed messages.
 * @param {Uint8Array} [apiId] An octet string containing the API identifier.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {[G1Projective, G1Projective, G1Projective, G1Projective, G1Projective, Scalar]} A vector containing 5 G1
 * points and a scalar.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-proof-initialization
 */
export function init(
  publicKey: Uint8Array,
  signature: [G1Projective, Scalar],
  generators: Array<G1Projective>,
  randomScalars: Array<Scalar>,
  header: Uint8Array = new Uint8Array(),
  messages: Array<Scalar> = new Array<Scalar>(),
  undisclosedIndexes: Array<number> = new Array<number>(),
  apiId: Uint8Array = new Uint8Array(),
  cipher: Cipher,
): [G1Projective, G1Projective, G1Projective, G1Projective, G1Projective, Scalar] {
  /**
   * Deserialization:
   *
   * 1. (A, e) := signature.
   * 2. L := len(messages).
   * 3. U := len(undisclosed_indexes).
   * 4. (j_1, j_2, ..., j_U) := undisclosed_indexes.
   * 5. If len(random_scalars) != U + 5, return INVALID.
   * 6. (r_1, r_2, ~e, ~r_1, ~r_3, ~m_{j_1}, ~m_{j_2}, ..., ~m_{j_U}) := random_scalars.
   * 7. (msg_1, msg_2, ..., msg_L) := messages.
   *
   * 8. If len(generators) != L + 1, return INVALID.
   * 9. (Q_1, MsgGenerators) := generators.
   * 10. (H_1, H_2, ..., H_L) := MsgGenerators.
   * 11. (H_{j_1}, H_{j_2}, ..., H_{j_U}) := (MsgGenerators[j_1], MsgGenerators[j_2], ..., MsgGenerators[j_U]).
   */
  const [A, e] = signature
  const l = messages.length
  const u = undisclosedIndexes.length

  if (randomScalars.length !== (u + 5)) {
    throw new Error("The number of random scalars must be equal to the number of undisclosed indexes plus five.")
  }

  const [r1, r2, eTilde, r1Tilde, r3Tilde, ...mTildes] = randomScalars

  if (generators.length !== (l + 1)) {
    throw new Error("The number of generators must be equal to the number of messages plus one.")
  }
  const [q1, ...hPoints] = generators
  const field = cipher.types.Fr

  /**
   * ABORT if:
   *
   * 1. For i in undisclosed_indexes, i < 0 or i > L - 1.
   * 2. U > L.
   */
  undisclosedIndexes.forEach((i) => {
    if (i < 0 || i > (l - 1)) {
      throw new Error("The undisclosed indexes must be in the range [0, L - 1].")
    }
  })
  if (u > l) {
    throw new Error("The number of undisclosed indexes must be less than or equal to the number of messages.")
  }

  /**
   * Procedure:
   *
   * 1. domain := calculate_domain(PK, Q_1, (H_1, H_2, ..., H_L) header, api_id).
   *
   * 2. B := P_1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L.
   * 3. D := B * r_2.
   * 4. A_bar := A * (r_1 * r_2).
   * 5. B_bar := D * r_1 - A_bar * e.
   *
   * 6. T_1 := A_bar * ~e + D * ~r_1.
   * 7. T_2 := D * ~r_3 + H_{j_1} * ~m_{j_1} + ... + H_{j_U} * ~m_{j_U}.
   *
   * 8. Return (A_bar, B_bar, D, T_1, T_2, domain).
   */
  const domain = calculateDomain(publicKey, generators[0], generators.slice(1), header, apiId, cipher)
  let b = cipher.p1.add(q1.multiply(domain))
  hPoints.forEach((h, i) => {
    b = b.add(h.multiply(messages[i]))
  })

  const d = b.multiply(r2)
  const aBar = A.multiply(field.mul(r1, r2))
  const bBar = d.multiply(r1).subtract(aBar.multiply(e))

  const t1 = aBar.multiply(eTilde).add(d.multiply(r1Tilde))
  let t2 = d.multiply(r3Tilde)
  undisclosedIndexes.forEach((j, i) => {
    t2 = t2.add(hPoints[j].multiply(mTildes[i]))
  })

  return [aBar, bBar, d, t1, t2, domain]
}

/**
 * Finalize the proof calculation and returns the serialized proof.
 *
 * This operation accepts the output of the initialization operation, and a scalar representing the challenge. It also
 * requires the scalar part `e` of the BBS signature, the random scalars used to generate the proof, and a set of
 * scalars representing the messages the prover wants to keep undisclosed. The undisclosed messages MUST be supplied in
 * the same order as in the sign operation.
 *
 * @param {Array} initOutput A vector containing 5 G1 points and a scalar, representing the value returned after
 * initializing the proof generation or verification operations.
 * @param {Scalar} challenge A scalar representing the challenge.
 * @param {Scalar} e A scalar representing the message.
 * @param {Array<Scalar>} randomScalars A vector of uniformly sampled random scalars.
 * @param {Array<Scalar>} [undisclosedMessages] A vector of scalars representing the undisclosed messages.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {Uint8Array} An octet string representing the proof.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-proof-finalization
 */
export function finalize(
  initOutput: [G1Projective, G1Projective, G1Projective, G1Projective, G1Projective, Scalar],
  challenge: Scalar,
  e: Scalar,
  randomScalars: Array<Scalar>,
  undisclosedMessages: Array<Scalar> = new Array<Scalar>(),
  cipher: Cipher,
): Uint8Array {
  /**
   * Deserialization:
   *
   * 1. U := len(undisclosed_messages).
   * 2. If len(random_scalars) != U + 5, return INVALID.
   * 3. (r_1, r_2, ~e, ~r_1, ~r_3, ~m_{j_1}, ~m_{j_2}, ..., ~m_{j_U}) := random_scalars.
   * 4. (undisclosed_1, undisclosed_2, ..., undisclosed_U) := undisclosed_messages.
   * 5. (A_bar, B_bar, D, _, _, _) := init_output.
   */
  const u = undisclosedMessages.length
  if (randomScalars.length !== (u + 5)) {
    throw new Error("The number of random scalars must be equal to the number of undisclosed messages plus five.")
  }
  const [r1, r2, eTilde, r1Tilde, r3Tilde, ...mTildes] = randomScalars
  const [aBar, bBar, d] = initOutput
  const field = cipher.types.Fr

  /**
   * Procedure:
   *
   * 1. r_3 := r_2 ^ {-1} mod r.
   * 2. ^e := ~e + e * challenge.
   * 3. ^r_1 := ~r_1 - r_1 * challenge.
   * 4. ^r_3 := ~r_3 - r_3 * challenge.
   * 5. For j in (1, ..., U): ^m_j := ~m_j + undisclosed_j * challenge mod r.
   *
   * 6. proof := (A_bar, B_bar, D, ^e, ^r_1, ^r_3, ^m_1, ^m_2, ..., ^m_U, challenge).
   * 7. Return proof_to_octets(proof).
   */
  const r3 = field.inv(r2)
  const eHat = field.add(eTilde, field.mul(e, challenge))
  const r1Hat = field.sub(r1Tilde, field.mul(r1, challenge))
  const r3Hat = field.sub(r3Tilde, field.mul(r3, challenge))
  const mHats = mTildes.map((m, j) => field.add(m, field.mul(undisclosedMessages[j], challenge)))
  return proofToOctets([aBar, bBar, d, eHat, r1Hat, r3Hat, mHats, challenge], cipher)
}

/**
 * Initialize the proof verification and returns part of the input that will be passed to the challenge calculation
 * operation.
 *
 * Note that the scalars representing the disclosed messages MUST be supplied in the same order as they were supplied to
 * the sign function. Similarly, the indexes of the disclosed messages MUST be supplied in ascending order.
 *
 * @param {Uint8Array} publicKey An octet string representing the public key.
 * @param {Array} proof A vector representing a BBS proof, containing 3 G1 points, 3 scalars, another nested but
 * possibly empty vector of scalars, and another scalar.
 * @param {Array<G1Projective>} generators A vector of pseudo-random points in G1.
 * @param {Uint8Array} [header] An octet string containing context and application specific information.
 * @param {Array<Scalar>} [disclosedMessages] A vector of scalars representing the disclosed messages.
 * @param {Array<number>} [disclosedIndexes] A vector representing the indexes of the disclosed messages.
 * @param {Uint8Array} [apiId] An octet string containing the API identifier.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {[G1Projective, G1Projective, G1Projective, Scalar]} A vector containing 3 G1 points and a scalar.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-proof-verification-initiali
 */
export function prepare(
  publicKey: Uint8Array,
  proof: [G1Projective, G1Projective, G1Projective, Scalar, Scalar, Scalar, Array<Scalar>, Scalar],
  generators: Array<G1Projective>,
  header: Uint8Array = new Uint8Array(),
  disclosedMessages: Array<Scalar> = new Array<Scalar>(),
  disclosedIndexes: Array<number> = new Array<number>(),
  apiId: Uint8Array = new Uint8Array(),
  cipher: Cipher,
): [G1Projective, G1Projective, G1Projective, G1Projective, G1Projective, Scalar] {
  /**
   * Deserialization:
   *
   * 1. (A_bar, B_bar, D, ^e, ^r_1, ^r_3, commitments, c) := proof.
   * 2. U := len(commitments).
   * 3. R := len(disclosed_indexes).
   * 4. L := R + U.
   * 5. (i_1, i_2, ..., i_R) := disclosed_indexes.
   * 6. For i in disclosed_indexes: if i < 0 or i > L - 1, return INVALID.
   * 7. (j_1, j_2, ..., j_U) := (0, 1, ..., L - 1) \ disclosed_indexes.
   * 8. If len(disclosed_messages) != R, return INVALID.
   * 9. (msg_{i_1}, msg_{i_2}, ..., msg_{i_R}) := disclosed_messages.
   * 10. (^m_{j_1}, ^m_{j_2}, ..., ^m_{j_U}) := commitments.
   *
   * 11. If len(generators) != L + 1, return INVALID.
   * 12. (Q_1, MsgGenerators) := generators.
   * 13. (H_1, H_2, ..., H_L) := MsgGenerators.
   * 14. (H_{i_1}, H_{i_2}, ..., H_{i_R}) := (MsgGenerators[i_1], MsgGenerators[i_2], ..., MsgGenerators[i_R]).
   * 15. (H_{j_1}, H_{j_2}, ..., H_{j_U}) := (MsgGenerators[j_1], MsgGenerators[j_2], ..., MsgGenerators[j_U]).
   */
  const [aBar, bBar, d, eHat, r1Hat, r3Hat, commitments, challenge] = proof
  const u = commitments.length
  const r = disclosedIndexes.length
  const l = r + u
  disclosedIndexes.forEach((i) => {
    if (i < 0 || i > (l - 1)) {
      throw new Error("The disclosed indexes must be in the range [0, L - 1].")
    }
  })

  if (generators.length !== (l + 1)) {
    throw new Error("The number of generators must be equal to the number of messages plus one.")
  }
  const [q1, ...hPoints] = generators
  const disclosedIndexesSet = new Set(disclosedIndexes)
  const undisclosedIndexes = [...hPoints.keys()].filter((i) => !disclosedIndexesSet.has(i))

  /**
   * Procedure:
   *
   * 1. domain := calculate_domain(PK, Q_1, (H_1, H_2, ..., H_L), header, api_id).
   * 2. T_1 := B_bar * c + A_bar * ^e + D * ^r_1.
   * 3. B_v := P_1 + Q_1 * domain + H_{i_1} * msg_{i_1} + ... + H_{i_R} * msg_{i_R}.
   * 4. T_2 := B_v * c + D * ^r_3 + H_{j_1} * ^m_{j_1} + ... + H_{j_U} * ^m_{j_U}.
   * 5. Return (A_bar, B_bar, D, T_1, T_2, domain).
   */
  const domain = calculateDomain(publicKey, generators[0], generators.slice(1), header, apiId, cipher)
  const t1 = bBar.multiply(challenge).add(aBar.multiply(eHat)).add(d.multiply(r1Hat))
  let bv = cipher.p1.add(q1.multiply(domain))
  disclosedMessages.forEach((msg, i) => {
    bv = bv.add(hPoints[disclosedIndexes[i]].multiply(msg))
  })

  let t2 = bv.multiply(challenge).add(d.multiply(r3Hat))
  commitments.forEach((mHat, j) => {
    t2 = t2.add(hPoints[undisclosedIndexes[j]].multiply(mHat))
  })
  return [aBar, bBar, d, t1, t2, domain]
}

/**
 * Calculate the challenge scalar used during proof generation and verification, as part of the Fiat-Shamir heuristic,
 * for making the proof protocol non-interactive. In a interactive setting, the challenge would be a random value
 * sampled by the verifier.
 *
 * At a high level, the challenge will be calculated as the digest of the following values:
 *     - The total number of the disclosed messages.
 *     - Each index in the `disclosed_indexes` list, followed by the corresponding disclosed message. For example, if
 *       `disclosed_indexes` is `[i_1, i_2]`, and `disclosed_messages` is `[msg_{i_1}, msg_{i_2}]`, then the input will
 *       include `i_1 || msg_{i_1} || i_2 || msg_{i_2}`.
 *     - The points `A_bar`, `B_bar`, `D`, `T_1`, `T_2`, and the `domain` scalar, calculated during the proof
 *       initialization phase.
 *     - The presentation header.
 *
 * @param {Array} initOutput A vector containing 5 G1 points and a scalar, representing the value returned after
 * initializing the proof generation or verification operations.
 * @param {Array<Scalar>} [disclosedMessages] A vector of scalars representing the disclosed messages.
 * @param {Array<number>} [disclosedIndexes] A vector representing the indexes of the disclosed messages.
 * @param {Uint8Array} [presentationHeader] An octet string containing the presentation header.
 * @param {Uint8Array} [apiId] An octet string containing the API identifier.
 * @param {Cipher} cipher A cipher suite.
 *
 * @returns {Scalar} A scalar representing the challenge.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-challenge-calculation
 */
export function challenge(
  initOutput: [G1Projective, G1Projective, G1Projective, G1Projective, G1Projective, Scalar],
  disclosedMessages: Array<Scalar> = new Array<Scalar>(),
  disclosedIndexes: Array<number> = new Array<number>(),
  presentationHeader: Uint8Array = new Uint8Array(),
  apiId: Uint8Array = new Uint8Array(),
  cipher: Cipher,
): Scalar {
  /**
   * Definitions:
   *
   * 1. hash_to_scalar_dst: an octet string representing the domain separation tag: <api_id> || "H2S_".
   */
  const hashToScalarDst = concatenate(apiId, new TextEncoder().encode("H2S_"))

  /**
   * Deserialization:
   *
   * 1. R := len(disclosed_indexes).
   * 2. (i_1, i_2, ..., i_R) := disclosed_indexes.
   * 3. If len(disclosed_messages) != R, return INVALID.
   * 4. (msg_{i_1}, msg_{i_2}, ..., msg_{i_R}) := disclosed_messages.
   * 5. (A_bar, B_bar, D, T_1, T_2, domain) := init_output.
   */
  const r = disclosedIndexes.length
  const [aBar, bBar, d, t1, t2, domain] = initOutput

  /**
   * ABORT if:
   *
   * 1. R > 2^64 - 1.
   * 2. len(presentation_header) > 2^64 - 1.
   */
  if (!Number.isSafeInteger(r)) {
    throw new Error("The number of disclosed indexes must be less than 2^64 - 1.")
  }
  if (!Number.isSafeInteger(presentationHeader.length)) {
    throw new Error("The length of the presentation header must be less than 2^64 - 1.")
  }
  if (disclosedMessages.length !== r) {
    throw new Error("The number of disclosed messages must be equal to the number of disclosed indexes.")
  }

  /**
   * Procedure:
   *
   * 1. c_arr := (R, i_1, msg_{i_1}, i_2, msg_{i_2}, ..., i_R, msg_{i_R}, A_bar, B_bar, D, T_1, T_2, domain).
   * 2. c_octs := serialize(c_arr) || I2OSP(len(presentation_header), 8) || presentation_header.
   * 3. return hash_to_scalar(c_octs, hash_to_scalar_dst).
   */
  const cArr = [r, ...disclosedIndexes.flatMap((x, i) => [x, disclosedMessages[i]]), aBar, bBar, d, t1, t2, domain]
  const cOcts = concatenate(serialize(cArr, cipher), i2osp(BigInt(presentationHeader.length), 8), presentationHeader)
  return hashToScalar(cOcts, hashToScalarDst, cipher)
}
