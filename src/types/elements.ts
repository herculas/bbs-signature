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

export function isE1Point(element: unknown): element is G1Projective {
  return typeof (<G1Projective> element).px === "bigint" &&
    typeof (<G1Projective> element).py === "bigint" &&
    typeof (<G1Projective> element).pz === "bigint"
}

export function isE2Point(element: unknown): element is G2Projective {
  return typeof (<G2Projective> element).px.c0 === "bigint" &&
    typeof (<G2Projective> element).px.c1 === "bigint" &&
    typeof (<G2Projective> element).py.c0 === "bigint" &&
    typeof (<G2Projective> element).py.c1 === "bigint" &&
    typeof (<G2Projective> element).pz.c0 === "bigint" &&
    typeof (<G2Projective> element).pz.c1 === "bigint"
}

export function isGtPoint(element: unknown): element is Gt {
  return typeof (<Gt> element).c0.c0.c0 === "bigint" &&
    typeof (<Gt> element).c0.c0.c1 === "bigint" &&
    typeof (<Gt> element).c0.c1.c0 === "bigint" &&
    typeof (<Gt> element).c0.c1.c1 === "bigint" &&
    typeof (<Gt> element).c0.c2.c0 === "bigint" &&
    typeof (<Gt> element).c0.c2.c1 === "bigint" &&
    typeof (<Gt> element).c1.c0.c0 === "bigint" &&
    typeof (<Gt> element).c1.c0.c1 === "bigint" &&
    typeof (<Gt> element).c1.c1.c0 === "bigint" &&
    typeof (<Gt> element).c1.c1.c1 === "bigint" &&
    typeof (<Gt> element).c1.c2.c0 === "bigint" &&
    typeof (<Gt> element).c1.c2.c1 === "bigint"
}
