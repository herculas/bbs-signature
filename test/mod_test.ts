import { assert, assertEquals, assertFalse } from "@std/assert"
import { bytesToNumberBE } from "@noble/curves/abstract/utils"
import { bls12_381 } from "@noble/curves/bls12-381"
import { randomBytes } from "@noble/hashes/utils"

import { isE1Point, isE2Point } from "../src/suite/elements.ts"
import { concatenate, os2ip } from "../src/utils/format.ts"


Deno.test("os2ip", () => {
  const random = randomBytes(32)
  const num1 = os2ip(random)
  const num2 = bytesToNumberBE(random)

  assertEquals(num1, num2)
})

Deno.test("concatenate", () => {
  const arr1 = new Uint8Array([1, 2, 3])
  const arr2 = new Uint8Array([4, 5, 6])
  const arr3 = new Uint8Array([7, 8, 9])
  const arr4 = new Uint8Array([10, 11, 12])
  const arr5 = new Uint8Array([13, 14, 15])

  const result = concatenate(arr1, arr2, arr3, arr4, arr5)

  assertEquals(result, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]))
})

Deno.test("type convert", () => {
  const a = { px: 1n, py: 2n, pz: 3n }
  const b = { px: { c0: 1n, c1: 1n }, py: { c0: 1n, c1: 1n }, pz: { c0: 1n, c1: 1n } }

  assert(isE1Point(a))
  assert(isE2Point(b))

  assertFalse(isE1Point(b))
  assertFalse(isE2Point(a))
})

Deno.test("a", () => {
  console.log(bls12_381.G1.ProjectivePoint)
})