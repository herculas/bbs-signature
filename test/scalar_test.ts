import { assertEquals } from "@std/assert"

import { BLS12_381_SHA_256, BLS12_381_SHAKE_256 } from "../src/suite/ciphers.ts"
import { bytesToHex, concatenate, hexToBytes, i2osp } from "../src/utils/format.ts"
import { seededRandomScalars } from "../src/utils/random.ts"
import { hashToScalar } from "../src/utils/hash.ts"

/**
 * Generate test vectors for random scalar generation.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-proof-fixtures
 */
Deno.test("shake-256 random scalar generation", () => {
  const cipher = BLS12_381_SHAKE_256
  const seed = hexToBytes("332e313431353932363533353839373933323338343632363433333833323739")
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const dst = concatenate(apiId, new TextEncoder().encode("MOCK_RANDOM_SCALARS_DST_"))
  const count = 10

  const scalars = seededRandomScalars(seed, dst, count, cipher)
  const scalarHex = scalars.map((scalar) => {
    const bytes = i2osp(scalar, cipher.octetScalarLength)
    return bytesToHex(bytes)
  })

  assertEquals(scalarHex[0], "1004262112c3eaa95941b2b0d1311c09c845db0099a50e67eda628ad26b43083")
  assertEquals(scalarHex[1], "6da7f145a94c1fa7f116b2482d59e4d466fe49c955ae8726e79453065156a9a4")
  assertEquals(scalarHex[2], "05017919b3607e78c51e8ec34329955d49c8c90e4488079c43e74824e98f1306")
  assertEquals(scalarHex[3], "4d451dad519b6a226bba79e11b44c441f1a74800eecfec6a2e2d79ea65b9d32d")
  assertEquals(scalarHex[4], "5e7e4894e6dbe68023bc92ef15c410b01f3828109fc72b3b5ab159fc427b3f51")
  assertEquals(scalarHex[5], "646e3014f49accb375253d268eb6c7f3289a1510f1e9452b612dd73a06ec5dd4")
  assertEquals(scalarHex[6], "363ecc4c1f9d6d9144374de8f1f7991405e3345a3ec49dd485a39982753c11a4")
  assertEquals(scalarHex[7], "12e592fe28d91d7b92a198c29afaa9d5329a4dcfdaf8b08557807412faeb4ac6")
  assertEquals(scalarHex[8], "513325acdcdec7ea572360587b350a8b095ca19bdd8258c5c69d375e8706141a")
  assertEquals(scalarHex[9], "6474fceba35e7e17365dde1a0284170180e446ae96c82943290d7baa3a6ed429")
})

/**
 * Generate test vectors for hash to scalar.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-hash-to-scalar-test-vectors
 */
Deno.test("shake-256 hash to scalar", () => {
  const cipher = BLS12_381_SHAKE_256
  const msg = hexToBytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
  const dst = hexToBytes(
    "4242535f424c53313233383147315f584f463a5348414b452d3235365f535357" +
      "555f524f5f4832475f484d32535f4832535f",
  )
  const scalar = hashToScalar(msg, dst, cipher)
  const scalarHex = bytesToHex(i2osp(scalar, cipher.octetScalarLength))

  assertEquals(scalarHex, "0500031f786fde5326aa9370dd7ffe9535ec7a52cf2b8f432cad5d9acfb73cd3")
})

/**
 * Generate test vectors for random scalar generation.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-proof-fixtures-2
 */
Deno.test("sha-256 random scalar generation", () => {
  const cipher = BLS12_381_SHA_256
  const seed = hexToBytes("332e313431353932363533353839373933323338343632363433333833323739")
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const dst = concatenate(apiId, new TextEncoder().encode("MOCK_RANDOM_SCALARS_DST_"))
  const count = 10

  const scalars = seededRandomScalars(seed, dst, count, cipher)
  const scalarHex = scalars.map((scalar) => {
    const bytes = i2osp(scalar, cipher.octetScalarLength)
    return bytesToHex(bytes)
  })

  assertEquals(scalarHex[0], "04f8e2518993c4383957ad14eb13a023c4ad0c67d01ec86eeb902e732ed6df3f")
  assertEquals(scalarHex[1], "5d87c1ba64c320ad601d227a1b74188a41a100325cecf00223729863966392b1")
  assertEquals(scalarHex[2], "0444607600ac70482e9c983b4b063214080b9e808300aa4cc02a91b3a92858fe")
  assertEquals(scalarHex[3], "548cd11eae4318e88cda10b4cd31ae29d41c3a0b057196ee9cf3a69d471e4e94")
  assertEquals(scalarHex[4], "2264b06a08638b69b4627756a62f08e0dc4d8240c1b974c9c7db779a769892f4")
  assertEquals(scalarHex[5], "4d99352986a9f8978b93485d21525244b21b396cf61f1d71f7c48e3fbc970a42")
  assertEquals(scalarHex[6], "5ed8be91662386243a6771fbdd2c627de31a44220e8d6f745bad5d99821a4880")
  assertEquals(scalarHex[7], "62ff1734b939ddd87beeb37a7bbcafa0a274cbc1b07384198f0e88398272208d")
  assertEquals(scalarHex[8], "05c2a0af016df58e844db8944082dcaf434de1b1e2e7136ec8a99b939b716223")
  assertEquals(scalarHex[9], "485e2adab17b76f5334c95bf36c03ccf91cef77dcfcdc6b8a69e2090b3156663")
})
