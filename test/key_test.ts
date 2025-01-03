import { assertEquals } from "@std/assert"
import { generateSecretKey, generatePublicKey } from "../src/keypair/keypair.ts"
import { BLS12_381_SHAKE_256 } from "../src/suite/ciphers.ts"
import { bytesToHex, hexToBytes, i2osp, os2ip } from "../src/utils/format.ts"

Deno.test("secret key generation", () => {
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

  const skInt = generateSecretKey(material, info, dst, BLS12_381_SHAKE_256)
  const skBytes = i2osp(skInt, 32)
  const skHex = bytesToHex(skBytes)

  assertEquals(skHex, "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079")
})

Deno.test("public key derivation", () => {
  const skHex = "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
  const skBytes = hexToBytes(skHex)
  const skInt = os2ip(skBytes)

  const pkBytes = generatePublicKey(skInt, BLS12_381_SHAKE_256)
  const pkHex = bytesToHex(pkBytes)

  assertEquals(
    pkHex,
    "92d37d1d6cd38fea3a873953333eab23" +
      "a4c0377e3e049974eb62bd45949cdeb1" +
      "8fb0490edcd4429adff56e65cbce42cf" +
      "188b31bddbd619e419b99c2c41b38179" +
      "eb001963bc3decaae0d9f702c7a8c004" +
      "f207f46c734a5eae2e8e82833f3e7ea5",
  )
})
