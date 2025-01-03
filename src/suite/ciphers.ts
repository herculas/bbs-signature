import { expand_message_xmd, expand_message_xof } from "@noble/curves/abstract/hash-to-curve"
import { bls12_381 } from "@noble/curves/bls12-381"
import { sha256 } from "@noble/hashes/sha2"
import { shake256 } from "@noble/hashes/sha3"

import { Cipher } from "../types/cipher.ts"
import { G1Projective, G2Projective, Gt } from "../types/elements.ts"

export const BLS12_381_SHAKE_256: Cipher = {
  id: new TextEncoder().encode("BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_"),
  hash: "SHAKE-256",

  octetScalarLength: 32,
  octetPointLength: 48,
  expandLength: 48,

  p1: bls12_381.G1.ProjectivePoint.fromHex(
    "8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755",
  ),

  types: {
    G1: bls12_381.G1.ProjectivePoint,
    G2: bls12_381.G2.ProjectivePoint,
    Fr: bls12_381.fields.Fr,
    Fpt: bls12_381.fields.Fp12,
  },

  hashToCurveG1(message: Uint8Array, dst: Uint8Array): G1Projective {
    if (dst.length > 255) {
      throw new Error("The length of dst should be less than or equal to 255")
    }
    return bls12_381.G1.hashToCurve(message, {
      DST: dst,
      expand: "xof",
      k: 128,
      hash: shake256,
    }) as G1Projective
  },

  expandMessage(message: Uint8Array, dst: Uint8Array, expandLength?: number): Uint8Array {
    if (dst.length > 255) {
      throw new Error("The length of dst should be less than or equal to 255")
    }
    return expand_message_xof(message, dst, expandLength ?? this.expandLength, 128, shake256)
  },

  pairing(point1: G1Projective, point2: G2Projective): Gt {
    return bls12_381.pairing(point1, point2)
  },

  pairingCompare(pair1: Gt, pair2: Gt, pair3: Gt): boolean {
    let result = this.types.Fpt.mul(pair1, pair2)
    result = this.types.Fpt.finalExponentiate(result)
    return this.types.Fpt.eql(result, pair3)
  },
}

export const BLS12_381_SHA_256: Cipher = {
  id: new TextEncoder().encode("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"),
  hash: "SHA-256",

  octetScalarLength: 32,
  octetPointLength: 48,
  expandLength: 48,

  p1: bls12_381.G1.ProjectivePoint.fromHex(
    "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9",
  ),

  types: {
    G1: bls12_381.G1.ProjectivePoint,
    G2: bls12_381.G2.ProjectivePoint,
    Fr: bls12_381.fields.Fr,
    Fpt: bls12_381.fields.Fp12,
  },

  hashToCurveG1(message: Uint8Array, dst: Uint8Array): G1Projective {
    if (dst.length > 255) {
      throw new Error("The length of dst should be less than or equal to 255")
    }
    return bls12_381.G1.hashToCurve(message, {
      DST: dst,
      expand: "xmd",
      hash: sha256,
    }) as G1Projective
  },

  expandMessage(message: Uint8Array, dst: Uint8Array, expandLength?: number): Uint8Array {
    if (dst.length > 255) {
      throw new Error("The length of dst should be less than or equal to 255")
    }
    return expand_message_xmd(message, dst, expandLength ?? this.expandLength, sha256)
  },

  pairing(point1: G1Projective, point2: G2Projective): Gt {
    return bls12_381.pairing(point1, point2)
  },

  pairingCompare(pair1: Gt, pair2: Gt, pair3: Gt): boolean {
    let result = this.types.Fpt.mul(pair1, pair2)
    result = this.types.Fpt.finalExponentiate(result)
    return this.types.Fpt.eql(result, pair3)
  },
}
