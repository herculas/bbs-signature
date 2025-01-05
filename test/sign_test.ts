import { assert, assertEquals } from "@std/assert"

import { BLS12_381_SHA_256, BLS12_381_SHAKE_256 } from "../src/suite/ciphers.ts"
import { sign, verify } from "../src/signature/core.ts"
import { calculateDomain } from "../src/utils/domain.ts"
import { bytesToHex, concatenate, hexToBytes, i2osp, os2ip } from "../src/utils/format.ts"
import { createGenerators, messagesToScalars } from "../src/utils/interface.ts"

/**
 * Test for signature generation and verification for single message, in BLS12-381-SHAKE-256.
 * 
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-single-message-signat
 */
Deno.test("shake-256 sign single message", () => {
  const headerBytes = hexToBytes("11223344556677889900aabbccddeeff")
  const msgBytes = hexToBytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
  const skBytes = hexToBytes("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079")
  const pkBytes = hexToBytes(
    "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
      "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
      "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
  )

  const cipher = BLS12_381_SHAKE_256
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(2, apiId, cipher)

  const domainInt = calculateDomain(pkBytes, generators[0], generators.slice(1), headerBytes, apiId, cipher)
  const domainBytes = i2osp(domainInt, cipher.octetScalarLength)
  const domainHex = bytesToHex(domainBytes)

  assertEquals(domainHex, "2f18dd269c11c512256a9d1d57e61a7d2de6ebcf41cac3053f37afedc4e650a9")

  const skInt = os2ip(skBytes)
  const msgs = messagesToScalars([msgBytes], apiId, cipher)
  const signature = sign(skInt, pkBytes, generators, headerBytes, msgs, apiId, cipher)
  const signatureHex = bytesToHex(signature)

  assertEquals(
    signatureHex,
    "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb7" +
      "1c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0" +
      "b97a12025a283d78b7136bb9825d04ef",
  )

  const verification = verify(pkBytes, signature, generators, headerBytes, msgs, apiId, cipher)
  assert(verification)
})

/**
 * Test for signature generation and verification for multiple messages, in BLS12-381-SHAKE-256.
 * 
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-multi-message-signatu
 */
Deno.test("shake-256 sign multiple messages", () => {
  const msg_1 = hexToBytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
  const msg_2 = hexToBytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80")
  const msg_3 = hexToBytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73")
  const msg_4 = hexToBytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c")
  const msg_5 = hexToBytes("496694774c5604ab1b2544eababcf0f53278ff50")
  const msg_6 = hexToBytes("515ae153e22aae04ad16f759e07237b4")
  const msg_7 = hexToBytes("d183ddc6e2665aa4e2f088af")
  const msg_8 = hexToBytes("ac55fb33a75909ed")
  const msg_9 = hexToBytes("96012096")
  const msg_10 = hexToBytes("")

  const headerBytes = hexToBytes("11223344556677889900aabbccddeeff")
  const skBytes = hexToBytes("2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079")
  const pkBytes = hexToBytes(
    "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
      "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
      "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
  )

  const cipher = BLS12_381_SHAKE_256
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(11, apiId, cipher)

  const domainInt = calculateDomain(pkBytes, generators[0], generators.slice(1), headerBytes, apiId, cipher)
  const domainBytes = i2osp(domainInt, cipher.octetScalarLength)
  const domainHex = bytesToHex(domainBytes)

  assertEquals(domainHex, "6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b")

  const skInt = os2ip(skBytes)
  const msgs = messagesToScalars([msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10], apiId, cipher)
  const signature = sign(skInt, pkBytes, generators, headerBytes, msgs, apiId, cipher)
  const signatureHex = bytesToHex(signature)

  assertEquals(
    signatureHex,
    "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08" +
      "faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67" +
      "fb7d3253e1e2acbcf90ef59a6911931e",
  )

  const verification = verify(pkBytes, signature, generators, headerBytes, msgs, apiId, cipher)
  assert(verification)
})

/**
 * Test for signature generation and verification for single message, in BLS12-381-SHA-256.
 * 
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-single-message-signatu
 */
Deno.test("sha-256 sign single message", () => {
  const headerBytes = hexToBytes("11223344556677889900aabbccddeeff")
  const msgBytes = hexToBytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
  const skBytes = hexToBytes("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc")
  const pkBytes = hexToBytes(
    "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
      "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
      "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
  )

  const cipher = BLS12_381_SHA_256
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(2, apiId, cipher)

  const domainInt = calculateDomain(pkBytes, generators[0], generators.slice(1), headerBytes, apiId, cipher)
  const domainBytes = i2osp(domainInt, cipher.octetScalarLength)
  const domainHex = bytesToHex(domainBytes)

  assertEquals(domainHex, "25d57fab92a8274c68fde5c3f16d4b275e4a156f211ae34b3ab32fbaf506ed5c")

  const skInt = os2ip(skBytes)
  const msgs = messagesToScalars([msgBytes], apiId, cipher)
  const signature = sign(skInt, pkBytes, generators, headerBytes, msgs, apiId, cipher)
  const signatureHex = bytesToHex(signature)

  assertEquals(
    signatureHex,
    "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da525" +
      "3aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb" +
      "4c892340be5969920d0916067b4565a0",
  )

  const verification = verify(pkBytes, signature, generators, headerBytes, msgs, apiId, cipher)
  assert(verification)
})

/**
 * Test for signature generation and verification for multiple messages, in BLS12-381-SHAKE-256.
 * 
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-multi-message-signatur
 */
Deno.test("sha-256 sign multiple messages", () => {
  const msg_1 = hexToBytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
  const msg_2 = hexToBytes("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80")
  const msg_3 = hexToBytes("7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73")
  const msg_4 = hexToBytes("77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c")
  const msg_5 = hexToBytes("496694774c5604ab1b2544eababcf0f53278ff50")
  const msg_6 = hexToBytes("515ae153e22aae04ad16f759e07237b4")
  const msg_7 = hexToBytes("d183ddc6e2665aa4e2f088af")
  const msg_8 = hexToBytes("ac55fb33a75909ed")
  const msg_9 = hexToBytes("96012096")
  const msg_10 = hexToBytes("")

  const headerBytes = hexToBytes("11223344556677889900aabbccddeeff")
  const skBytes = hexToBytes("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc")
  const pkBytes = hexToBytes(
    "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
      "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
      "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
  )

  const cipher = BLS12_381_SHA_256
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(11, apiId, cipher)

  const domainInt = calculateDomain(pkBytes, generators[0], generators.slice(1), headerBytes, apiId, cipher)
  const domainBytes = i2osp(domainInt, cipher.octetScalarLength)
  const domainHex = bytesToHex(domainBytes)

  assertEquals(domainHex, "6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47")

  const skInt = os2ip(skBytes)
  const msgs = messagesToScalars([msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10], apiId, cipher)
  const signature = sign(skInt, pkBytes, generators, headerBytes, msgs, apiId, cipher)
  const signatureHex = bytesToHex(signature)

  assertEquals(
    signatureHex,
    "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146" +
      "3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36" +
      "32078557b2ace7d44caed846e1a0a1e8",
  )

  const verification = verify(pkBytes, signature, generators, headerBytes, msgs, apiId, cipher)
  assert(verification)
})
