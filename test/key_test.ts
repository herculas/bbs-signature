import { assertEquals } from "@std/assert"

import { generatePublicKey, generateSecretKey } from "../src/keypair/keypair.ts"
import { BLS12_381_SHA_256, BLS12_381_SHAKE_256 } from "../src/suite/ciphers.ts"
import { bytesToHex, hexToBytes, i2osp, os2ip } from "../src/utils/format.ts"

/**
 * Test for secret key generation using BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-key-pair
 */
Deno.test("shake-256 secret key generation", () => {
  const material = hexToBytes(
    "746869732d49532d6a7573742d616e2d" +
      "546573742d494b4d2d746f2d67656e65" +
      "726174652d246528724074232d6b6579",
  )
  const info = hexToBytes(
    "746869732d49532d736f6d652d6b6579" +
      "2d6d657461646174612d746f2d62652d" +
      "757365642d696e2d746573742d6b6579" +
      "2d67656e",
  )
  const dst = hexToBytes(
    "4242535f424c53313233383147315f58" +
      "4f463a5348414b452d3235365f535357" +
      "555f524f5f4832475f484d32535f4b45" +
      "5947454e5f4453545f",
  )

  const cipher = BLS12_381_SHAKE_256
  const skInt = generateSecretKey(material, info, dst, cipher)
  const skBytes = i2osp(skInt, cipher.octetScalarLength)
  const skHex = bytesToHex(skBytes)

  assertEquals(skHex, "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079")
})

/**
 * Test for public key derivation using BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-key-pair
 */
Deno.test("shake-256 public key derivation", () => {
  const skHex = "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
  const skBytes = hexToBytes(skHex)
  const skInt = os2ip(skBytes)

  const cipher = BLS12_381_SHAKE_256
  const pkBytes = generatePublicKey(skInt, cipher)
  const pkHex = bytesToHex(pkBytes)

  assertEquals(
    pkHex,
    "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
      "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
      "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
  )
})

/**
 * Test for secret key generation using BLS12-381-SHA-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-key-pair-2
 */
Deno.test("sha-256 secret key generation", () => {
  const material = hexToBytes(
    "746869732d49532d6a7573742d616e2d" +
      "546573742d494b4d2d746f2d67656e65" +
      "726174652d246528724074232d6b6579",
  )

  const info = hexToBytes(
    "746869732d49532d736f6d652d6b6579" +
      "2d6d657461646174612d746f2d62652d" +
      "757365642d696e2d746573742d6b6579" +
      "2d67656e",
  )

  const dst = hexToBytes(
    "4242535f424c53313233383147315f58" +
      "4d443a5348412d3235365f535357555f" +
      "524f5f4832475f484d32535f4b455947" +
      "454e5f4453545f",
  )

  const cipher = BLS12_381_SHA_256
  const skInt = generateSecretKey(material, info, dst, cipher)
  const skBytes = i2osp(skInt, cipher.octetScalarLength)
  const skHex = bytesToHex(skBytes)

  assertEquals(skHex, "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc")
})

/**
 * Test for public key derivation using BLS12-381-SHA-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-key-pair-2
 */
Deno.test("sha-256 public key derivation", () => {
  const skHex = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const skBytes = hexToBytes(skHex)
  const skInt = os2ip(skBytes)

  const cipher = BLS12_381_SHA_256
  const pkBytes = generatePublicKey(skInt, cipher)
  const pkHex = bytesToHex(pkBytes)

  assertEquals(
    pkHex,
    "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
      "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
      "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
  )
})
