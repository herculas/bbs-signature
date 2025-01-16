import { assert, assertEquals, assertFalse } from "@std/assert"
import { sign, verify } from "../lib/mod.ts"

/**
 * Test for signature generation and verification for single message, in BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-single-message-signat
 */
Deno.test("shake-256 sign single message", () => {
  const header = "11223344556677889900aabbccddeeff"
  const message = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"

  const secretKey = "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

  const signature = sign(secretKey, publicKey, header, [message], "BLS12_381_G1_XOF_SHAKE_256")
  const verification = verify(publicKey, signature, header, [message], "BLS12_381_G1_XOF_SHAKE_256")

  assertEquals(
    signature,
    "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb7" +
      "1c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0" +
      "b97a12025a283d78b7136bb9825d04ef",
  )
  assert(verification)
})

/**
 * Test for signature generation and verification for multiple messages, in BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-multi-message-signatu
 */
Deno.test("shake-256 sign multiple messages", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const header = "11223344556677889900aabbccddeeff"

  const msg_1 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const msg_2 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const msg_3 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const msg_4 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const msg_5 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const msg_6 = "515ae153e22aae04ad16f759e07237b4"
  const msg_7 = "d183ddc6e2665aa4e2f088af"
  const msg_8 = "ac55fb33a75909ed"
  const msg_9 = "96012096"
  const msg_10 = ""
  const messages = [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10]

  const privateKey = "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

  const signature = sign(privateKey, publicKey, header, messages, cipher)
  const verification = verify(publicKey, signature, header, messages, cipher)

  assertEquals(
    signature,
    "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08" +
      "faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67" +
      "fb7d3253e1e2acbcf90ef59a6911931e",
  )
  assert(verification)
})

/**
 * Test for signature generation and verification with no header, in BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-no-header-valid-signature
 */
Deno.test("shake-256 no header valid signature", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const header = undefined

  const msg_1 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const msg_2 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const msg_3 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const msg_4 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const msg_5 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const msg_6 = "515ae153e22aae04ad16f759e07237b4"
  const msg_7 = "d183ddc6e2665aa4e2f088af"
  const msg_8 = "ac55fb33a75909ed"
  const msg_9 = "96012096"
  const msg_10 = ""
  const messages = [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10]

  const privateKey = "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

  const signature = sign(privateKey, publicKey, header, messages, cipher)
  const verification = verify(publicKey, signature, header, messages, cipher)

  assertEquals(
    signature,
    "88beeb970f803160d3058eacde505207c576a8c9e4e5dc7c5249cbcf2a046c15" +
      "f8df047031eef3436e04b779d92a9cdb1fe4c6cc035ba1634f1740f9dd49816d" +
      "3ca745ecbe39f655ea61fb700137fded",
  )
  assert(verification)
})

/**
 * Test for signature generation and verification with modified message, in BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-modified-message-signature
 */
Deno.test("shake-256 modified message signature", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const header = "11223344556677889900aabbccddeeff"

  const message = ""

  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"
  const signature = "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb7" +
    "1c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0" +
    "b97a12025a283d78b7136bb9825d04ef"

  const verification = verify(publicKey, signature, header, [message], cipher)
  assertFalse(verification)
})

/**
 * Test for signature generation and verification with extra unsigned signature, in BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-extra-unsigned-message-sign
 */
Deno.test("shake-256 extra unsigned message signature", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const header = "11223344556677889900aabbccddeeff"

  const msg_1 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const msg_2 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const messages = [msg_1, msg_2]

  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"
  const signature = "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb7" +
    "1c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0" +
    "b97a12025a283d78b7136bb9825d04ef"

  const verification = verify(publicKey, signature, header, messages, cipher)
  assertFalse(verification)
})

/**
 * Test for signature generation and verification with missing message, in BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-missing-message-signature
 */
Deno.test("shake-256 missing message signature", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const header = "11223344556677889900aabbccddeeff"

  const msg_1 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const msg_2 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const messages = [msg_1, msg_2]

  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"
  const signature = "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08" +
    "faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67" +
    "fb7d3253e1e2acbcf90ef59a6911931e"

  const verification = verify(publicKey, signature, header, messages, cipher)
  assertFalse(verification)
})

/**
 * Test for signature generation and verification with reordered messages, in BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-reordered-message-signature
 */
Deno.test("shake-256 reordered message signature", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const header = "11223344556677889900aabbccddeeff"

  const msg_1 = ""
  const msg_2 = "96012096"
  const msg_3 = "ac55fb33a75909ed"
  const msg_4 = "d183ddc6e2665aa4e2f088af"
  const msg_5 = "515ae153e22aae04ad16f759e07237b4"
  const msg_6 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const msg_7 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const msg_8 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const msg_9 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const msg_10 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const messages = [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10]

  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"
  const signature = "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08" +
    "faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67" +
    "fb7d3253e1e2acbcf90ef59a6911931e"

  const verification = verify(publicKey, signature, header, messages, cipher)
  assertFalse(verification)
})

/**
 * Test for signature generation and verification with wrong public key, in BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-wrong-public-key-signature
 */
Deno.test("shake-256 wrong public key signature", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const header = "11223344556677889900aabbccddeeff"

  const msg_1 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const msg_2 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const msg_3 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const msg_4 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const msg_5 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const msg_6 = "515ae153e22aae04ad16f759e07237b4"
  const msg_7 = "d183ddc6e2665aa4e2f088af"
  const msg_8 = "ac55fb33a75909ed"
  const msg_9 = "96012096"
  const msg_10 = ""
  const messages = [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10]

  const publicKey = "b24c723803f84e210f7a95f6265c5cbfa4ecc51488bf7acf24b921807801c079" +
    "8b725b9a2dcfa29953efcdfef03328720196c78b2e613727fd6e085302a0cc2d" +
    "8d7e1d820cf1d36b20e79eee78c13a1a5da51a298f1aef86f07bc33388f089d8"
  const signature = "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08" +
    "faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67" +
    "fb7d3253e1e2acbcf90ef59a6911931e"

  const verification = verify(publicKey, signature, header, messages, cipher)
  assertFalse(verification)
})

/**
 * Test for signature generation and verification with wrong header, in BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-wrong-header-signature
 */
Deno.test("shake-256 wrong header valid signature", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const header = "ffeeddccbbaa00998877665544332211"

  const msg_1 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const msg_2 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const msg_3 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const msg_4 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const msg_5 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const msg_6 = "515ae153e22aae04ad16f759e07237b4"
  const msg_7 = "d183ddc6e2665aa4e2f088af"
  const msg_8 = "ac55fb33a75909ed"
  const msg_9 = "96012096"
  const msg_10 = ""
  const messages = [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10]

  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"
  const signature = "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08" +
    "faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67" +
    "fb7d3253e1e2acbcf90ef59a6911931e"

  const verification = verify(publicKey, signature, header, messages, cipher)
  assertFalse(verification)
})

/**
 * Test for signature generation and verification for single message, in BLS12-381-SHA-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-single-message-signatu
 */
Deno.test("sha-256 sign single message", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = "11223344556677889900aabbccddeeff"

  const message = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"

  const privateKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const signature = sign(privateKey, publicKey, header, [message], cipher)
  const verification = verify(publicKey, signature, header, [message], cipher)

  assertEquals(
    signature,
    "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da525" +
      "3aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb" +
      "4c892340be5969920d0916067b4565a0",
  )
  assert(verification)
})

/**
 * Test for signature generation and verification for multiple messages, in BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-multi-message-signatur
 */
Deno.test("sha-256 sign multiple messages", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = "11223344556677889900aabbccddeeff"

  const msg_1 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const msg_2 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const msg_3 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const msg_4 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const msg_5 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const msg_6 = "515ae153e22aae04ad16f759e07237b4"
  const msg_7 = "d183ddc6e2665aa4e2f088af"
  const msg_8 = "ac55fb33a75909ed"
  const msg_9 = "96012096"
  const msg_10 = ""
  const messages = [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10]

  const privateKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const signature = sign(privateKey, publicKey, header, messages, cipher)
  const verification = verify(publicKey, signature, header, messages, cipher)

  assertEquals(
    signature,
    "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146" +
      "3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36" +
      "32078557b2ace7d44caed846e1a0a1e8",
  )
  assert(verification)
})

/**
 * Test for signature generation and verification with no header, in BLS12-381-SHA-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-no-header-valid-signature-2
 */
Deno.test("sha-256 no header valid signature", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = undefined

  const msg_1 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const msg_2 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const msg_3 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const msg_4 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const msg_5 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const msg_6 = "515ae153e22aae04ad16f759e07237b4"
  const msg_7 = "d183ddc6e2665aa4e2f088af"
  const msg_8 = "ac55fb33a75909ed"
  const msg_9 = "96012096"
  const msg_10 = ""
  const messages = [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10]

  const privateKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const signature = sign(privateKey, publicKey, header, messages, cipher)
  const verification = verify(publicKey, signature, header, messages, cipher)

  assertEquals(
    signature,
    "8c87e2080859a97299c148427cd2fcf390d24bea850103a9748879039262ecf4" +
      "f42206f6ef767f298b6a96b424c1e86c26f8fba62212d0e05b95261c2cc0e5fd" +
      "c63a32731347e810fd12e9c58355aa0d",
  )
  assert(verification)
})

/**
 * Test for signature generation and verification with modified message, in BLS12-381-SHA-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-modified-message-signature-2
 */
Deno.test("sha-256 modified message signature", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = "11223344556677889900aabbccddeeff"

  const message = ""

  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"
  const signature = "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da525" +
    "3aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb" +
    "4c892340be5969920d0916067b4565a0"

  const verification = verify(publicKey, signature, header, [message], cipher)
  assertFalse(verification)
})

/**
 * Test for signature generation and verification with extra unsigned signature, in BLS12-381-SHA-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-extra-unsigned-message-signa
 */
Deno.test("sha-256 extra unsigned message signature", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = "11223344556677889900aabbccddeeff"

  const msg_1 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const msg_2 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const messages = [msg_1, msg_2]

  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"
  const signature = "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da525" +
    "3aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb" +
    "4c892340be5969920d0916067b4565a0"

  const verification = verify(publicKey, signature, header, messages, cipher)
  assertFalse(verification)
})

/**
 * Test for signature generation and verification with missing message, in BLS12-381-SHA-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-missing-message-signature-2
 */
Deno.test("sha-256 missing message signature", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = "11223344556677889900aabbccddeeff"

  const msg_1 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const msg_2 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const messages = [msg_1, msg_2]

  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"
  const signature = "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146" +
    "3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36" +
    "32078557b2ace7d44caed846e1a0a1e8"

  const verification = verify(publicKey, signature, header, messages, cipher)
  assertFalse(verification)
})

/**
 * Test for signature generation and verification with reordered messages, in BLS12-381-SHA-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-reordered-message-signature-2
 */
Deno.test("sha-256 reordered message signature", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = "11223344556677889900aabbccddeeff"

  const msg_1 = ""
  const msg_2 = "96012096"
  const msg_3 = "ac55fb33a75909ed"
  const msg_4 = "d183ddc6e2665aa4e2f088af"
  const msg_5 = "515ae153e22aae04ad16f759e07237b4"
  const msg_6 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const msg_7 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const msg_8 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const msg_9 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const msg_10 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const messages = [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10]

  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"
  const signature = "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146" +
    "3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36" +
    "32078557b2ace7d44caed846e1a0a1e8"

  const verification = verify(publicKey, signature, header, messages, cipher)
  assertFalse(verification)
})

/**
 * Test for signature generation and verification with wrong public key, in BLS12-381-SHA-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-wrong-public-key-signature-2
 */
Deno.test("sha-256 wrong public key signature", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = "11223344556677889900aabbccddeeff"

  const msg_1 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const msg_2 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const msg_3 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const msg_4 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const msg_5 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const msg_6 = "515ae153e22aae04ad16f759e07237b4"
  const msg_7 = "d183ddc6e2665aa4e2f088af"
  const msg_8 = "ac55fb33a75909ed"
  const msg_9 = "96012096"
  const msg_10 = ""
  const messages = [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10]

  const publicKey = "b064bd8d1ba99503cbb7f9d7ea00bce877206a85b1750e5583dd9399828a4d20" +
    "610cb937ea928d90404c239b2835ffb104220a9c66a4c9ed3b54c0cac9ea465d" +
    "0429556b438ceefb59650ddf67e7a8f103677561b7ef7fe3c3357ec6b94d41c6"
  const signature = "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146" +
    "3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36" +
    "32078557b2ace7d44caed846e1a0a1e8"

  const verification = verify(publicKey, signature, header, messages, cipher)
  assertFalse(verification)
})

/**
 * Test for signature generation and verification with wrong header, in BLS12-381-SHA-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-wrong-header-signature-2
 */
Deno.test("sha-256 wrong header valid signature", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = "ffeeddccbbaa00998877665544332211"

  const msg_1 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const msg_2 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const msg_3 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const msg_4 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const msg_5 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const msg_6 = "515ae153e22aae04ad16f759e07237b4"
  const msg_7 = "d183ddc6e2665aa4e2f088af"
  const msg_8 = "ac55fb33a75909ed"
  const msg_9 = "96012096"
  const msg_10 = ""
  const messages = [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10]

  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"
  const signature = "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146" +
    "3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36" +
    "32078557b2ace7d44caed846e1a0a1e8"

  const verification = verify(publicKey, signature, header, messages, cipher)
  assertFalse(verification)
})
