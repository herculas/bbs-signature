import { assert } from "@std/assert"
import { prove, validate } from "../lib/mod.ts"

/**
 * Valid single message proof generation.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-single-message-proof
 */
Deno.test("shake-256 proof for single message", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const header = "11223344556677889900aabbccddeeff"
  const presentationHeader = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501"

  const message = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"

  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"
  const signature = "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb7" +
    "1c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0" +
    "b97a12025a283d78b7136bb9825d04ef"

  const proof = prove(publicKey, signature, header, presentationHeader, [message], [0], cipher)
  const verification = validate(publicKey, proof, header, presentationHeader, [message], [0], cipher)
  assert(verification)
})

/**
 * Valid proof for multiple messages, all disclosed.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-multi-message-all-mes
 */
Deno.test("shake-256 proof for multiple message, all disclosed", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const header = "11223344556677889900aabbccddeeff"
  const presentationHeader = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501"

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

  const disclosedIndexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  const disclosedMessages = messages.filter((_, i) => disclosedIndexes.includes(i))

  const proof = prove(publicKey, signature, header, presentationHeader, messages, disclosedIndexes, cipher)
  const verification = validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    disclosedMessages,
    disclosedIndexes,
    cipher,
  )

  assert(verification)
})

/**
 * Valid proof for multiple messages, partial disclosed.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-multi-message-some-me
 */
Deno.test("shake-256 proof for multiple message, partial disclosed", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const headerBytes = "11223344556677889900aabbccddeeff"
  const presentationHeaderBytes = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501"

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

  const disclosedIndexes = [0, 2, 4, 6]
  const disclosedMessages = messages.filter((_, i) => disclosedIndexes.includes(i))

  const proof = prove(publicKey, signature, headerBytes, presentationHeaderBytes, messages, disclosedIndexes, cipher)
  const verification = validate(
    publicKey,
    proof,
    headerBytes,
    presentationHeaderBytes,
    disclosedMessages,
    disclosedIndexes,
    cipher,
  )

  assert(verification)
})

/**
 * Valid proof for multiple messages, partial disclosed, no header.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-no-header-valid-proof
 */
Deno.test("shake-256 proof for multiple message, partial disclosed, no header", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const header = undefined
  const presentationHeader = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501"

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
  const signature = "88beeb970f803160d3058eacde505207c576a8c9e4e5dc7c5249cbcf2a046c15" +
    "f8df047031eef3436e04b779d92a9cdb1fe4c6cc035ba1634f1740f9dd49816d" +
    "3ca745ecbe39f655ea61fb700137fded"

  const disclosedIndexes = [0, 2, 4, 6]
  const disclosedMessages = messages.filter((_, i) => disclosedIndexes.includes(i))

  const proof = prove(publicKey, signature, header, presentationHeader, messages, disclosedIndexes, cipher)
  const verification = validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    disclosedMessages,
    disclosedIndexes,
    cipher,
  )
  assert(verification)
})

/**
 * Valid proof for multiple messages, partial disclosed, no presentation header.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-no-presentation-header-vali
 */
Deno.test("shake-256 proof for multiple message, partial disclosed, no presentation header", () => {
  const cipher = "BLS12_381_G1_XOF_SHAKE_256"
  const headerBytes = "11223344556677889900aabbccddeeff"
  const presentationHeaderBytes = undefined

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

  const pkBytes = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

  const signatureBytes = "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08" +
    "faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67" +
    "fb7d3253e1e2acbcf90ef59a6911931e"

  const disclosedIndexes = [0, 2, 4, 6]
  const disclosedMessages = messages.filter((_, i) => disclosedIndexes.includes(i))

  const proof = prove(pkBytes, signatureBytes, headerBytes, presentationHeaderBytes, messages, disclosedIndexes, cipher)
  const verification = validate(
    pkBytes,
    proof,
    headerBytes,
    presentationHeaderBytes,
    disclosedMessages,
    disclosedIndexes,
    cipher,
  )
  assert(verification)
})

/**
 * Valid single message proof generation.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-single-message-proof-2
 */
Deno.test("sha-256 proof for single message", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = "11223344556677889900aabbccddeeff"
  const presentationHeader = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501"

  const message = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const messages = [message]

  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"
  const signature = "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da525" +
    "3aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb" +
    "4c892340be5969920d0916067b4565a0"

  const disclosedIndexes: Array<number> = [0]
  const disclosedMessages = messages.filter((_, i) => disclosedIndexes.includes(i))

  const proof = prove(publicKey, signature, header, presentationHeader, messages, disclosedIndexes, cipher)
  const verification = validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    disclosedMessages,
    disclosedIndexes,
    cipher,
  )
  assert(verification)
})

/**
 * Valid proof for multiple messages, all disclosed.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-multi-message-all-mess
 */
Deno.test("sha-256 proof for multiple message, all disclosed", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = "11223344556677889900aabbccddeeff"
  const presentationHeader = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501"

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

  const disclosedIndexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  const disclosedMessages = messages.filter((_, i) => disclosedIndexes.includes(i))

  const proof = prove(publicKey, signature, header, presentationHeader, messages, disclosedIndexes, cipher)
  const verification = validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    disclosedMessages,
    disclosedIndexes,
    cipher,
  )
  assert(verification)
})

/**
 * Valid proof for multiple messages, partial disclosed.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-multi-message-some-mes
 */
Deno.test("sha-256 proof for multiple message, partial disclosed", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = "11223344556677889900aabbccddeeff"
  const presentationHeader = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501"

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

  const disclosedIndexes = [0, 2, 4, 6]
  const disclosedMessages = messages.filter((_, i) => disclosedIndexes.includes(i))

  const proof = prove(publicKey, signature, header, presentationHeader, messages, disclosedIndexes, cipher)
  const verification = validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    disclosedMessages,
    disclosedIndexes,
    cipher,
  )
  assert(verification)
})

/**
 * Valid proof for multiple messages, partial disclosed, no header.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-no-header-valid-proof-2
 */
Deno.test("sha-256 proof for multiple message, partial disclosed, no header", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const header = undefined
  const presentationHeader = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501"

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
  const signature = "8c87e2080859a97299c148427cd2fcf390d24bea850103a9748879039262ecf4" +
    "f42206f6ef767f298b6a96b424c1e86c26f8fba62212d0e05b95261c2cc0e5fd" +
    "c63a32731347e810fd12e9c58355aa0d"

  const disclosedIndexes = [0, 2, 4, 6]
  const disclosedMessages = messages.filter((_, i) => disclosedIndexes.includes(i))

  const proof = prove(publicKey, signature, header, presentationHeader, messages, disclosedIndexes, cipher)
  const verification = validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    disclosedMessages,
    disclosedIndexes,
    cipher,
  )
  assert(verification)
})

/**
 * Valid proof for multiple messages, partial disclosed, no presentation header.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-no-presentation-header-valid
 */
Deno.test("sha-256 proof for multiple message, partial disclosed, no presentation header", () => {
  const cipher = "BLS12_381_G1_XMD_SHA_256"
  const headerBytes = "11223344556677889900aabbccddeeff"
  const presentationHeaderBytes = undefined

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

  const disclosedIndexes = [0, 2, 4, 6]
  const disclosedMessages = messages.filter((_, i) => disclosedIndexes.includes(i))

  const proof = prove(publicKey, signature, headerBytes, presentationHeaderBytes, messages, disclosedIndexes, cipher)
  const verification = validate(
    publicKey,
    proof,
    headerBytes,
    presentationHeaderBytes,
    disclosedMessages,
    disclosedIndexes,
    cipher,
  )
  assert(verification)
})
