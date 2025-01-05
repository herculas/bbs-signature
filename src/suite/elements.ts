import { ProjConstructor, ProjPointType } from "@noble/curves/abstract/weierstrass"
import { Fp12, Fp12Bls, Fp2 } from "@noble/curves/abstract/tower"
import { IField } from "@noble/curves/abstract/modular"

// scalar and point definition
export type G1Projective = ProjPointType<bigint>
export type G2Projective = ProjPointType<Fp2>
export type Gt = Fp12
export type Scalar = bigint

// field and group types
export type G1 = ProjConstructor<bigint>
export type G2 = ProjConstructor<Fp2>
export type Fpt = Fp12Bls
export type Fr = IField<Scalar>

export function isFp2(element: unknown): element is Fp2 {
  return typeof (<Fp2> element).c0 !== "undefined" && typeof (<Fp2> element).c0 === "bigint" &&
    typeof (<Fp2> element).c1 !== "undefined" && typeof (<Fp2> element).c1 === "bigint"
}

export function isE1Point(element: unknown): element is G1Projective {
  // element has three properties, px, py, and pz, each of which is a bigint
  return typeof (<G1Projective> element).px !== "undefined" && typeof (<G1Projective> element).px === "bigint" &&
    typeof (<G1Projective> element).py !== "undefined" && typeof (<G1Projective> element).py === "bigint" &&
    typeof (<G1Projective> element).pz !== "undefined" && typeof (<G1Projective> element).pz === "bigint"
}

export function isE2Point(element: unknown): element is G2Projective {
  // element has three properties, px, py, and pz, each of which is an Fp2
  return typeof (<G2Projective> element).px !== "undefined" && isFp2((<G2Projective> element).px) &&
    typeof (<G2Projective> element).py !== "undefined" && isFp2((<G2Projective> element).py) &&
    typeof (<G2Projective> element).pz !== "undefined" && isFp2((<G2Projective> element).pz)
}
