import { assertEquals } from "@std/assert"

import * as key from "../lib/key.ts"
import * as CONSTANT from "../lib/constants.ts"

Deno.test("Shake-256 key generation", () => {
  const cipher = CONSTANT.Cipher.XOF_SHAKE_256

  const material = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65" +
    "726174652d246528724074232d6b6579"
  const info = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d" +
    "757365642d696e2d746573742d6b65792d67656e"
  const dst = "4242535f424c53313233383147315f584f463a5348414b452d3235365f535357" +
    "555f524f5f4832475f484d32535f4b455947454e5f4453545f"

  const { secretKey, publicKey } = key.createPair(material, info, dst, cipher)

  assertEquals(secretKey, "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079")
  assertEquals(
    publicKey,
    "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
      "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
      "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
  )
})

Deno.test("Sha-256 key generation", () => {
  const cipher = CONSTANT.Cipher.XMD_SHA_256

  const material = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65" +
    "726174652d246528724074232d6b6579"
  const info = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d" +
    "757365642d696e2d746573742d6b65792d67656e"
  const dst = "4242535f424c53313233383147315f584d443a5348412d3235365f535357555f" +
    "524f5f4832475f484d32535f4b455947454e5f4453545f"

  const { secretKey, publicKey } = key.createPair(material, info, dst, cipher)

  assertEquals(secretKey, "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc")
  assertEquals(
    publicKey,
    "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
      "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
      "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
  )
})
