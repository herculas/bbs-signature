import { assert, assertEquals } from "@std/assert"

import { BLS12_381_SHA_256, BLS12_381_SHAKE_256 } from "../src/suite/ciphers.ts"
import { bytesToHex, concatenate, hexToBytes, os2ip } from "../src/utils/format.ts"
import { challenge, finalize, init } from "../src/proof/subroutines.ts"
import { octetsToSignature } from "../src/utils/serialize.ts"
import { createGenerators, messagesToScalars } from "../src/utils/interface.ts"
import { serialize } from "../src/utils/serialize.ts"
import { verify } from "../src/proof/core.ts"

/**
 * Valid single message proof generation.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-single-message-proof
 */
Deno.test("shake-256 proof for single message", () => {
  const cipher = BLS12_381_SHAKE_256
  const headerBytes = hexToBytes("11223344556677889900aabbccddeeff")
  const presentationHeaderBytes = hexToBytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
  const msgBytes = hexToBytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
  const pkBytes = hexToBytes(
    "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
      "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
      "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
  )
  const signatureBytes = hexToBytes(
    "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb7" +
      "1c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0" +
      "b97a12025a283d78b7136bb9825d04ef",
  )
  const r1 = os2ip(hexToBytes("1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881"))
  const r2 = os2ip(hexToBytes("25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd"))
  const eTilde = os2ip(hexToBytes("5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c"))
  const r1Tilde = os2ip(hexToBytes("3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58"))
  const r3Tilde = os2ip(hexToBytes("016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2"))

  const [a, e] = octetsToSignature(signatureBytes, cipher)
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(2, apiId, cipher)
  const randoms = [r1, r2, eTilde, r1Tilde, r3Tilde]
  const msgs = messagesToScalars([msgBytes], apiId, cipher)

  const disclosedIndexes: Array<number> = [0]
  const undisclosedIndexes: Array<number> = []
  const disclosedMessages = msgs.filter((_, i) => disclosedIndexes.includes(i))
  const undisclosedMessages = msgs.filter((_, i) => undisclosedIndexes.includes(i))

  const initRes = init(pkBytes, [a, e], generators, randoms, headerBytes, msgs, undisclosedIndexes, apiId, cipher)
  const c = challenge(initRes, disclosedMessages, disclosedIndexes, presentationHeaderBytes, apiId, cipher)
  const proof = finalize(initRes, c, e, randoms, undisclosedMessages, cipher)

  assertEquals(
    bytesToHex(serialize([initRes[3]], cipher)),
    "91a10e73cf4090812e8ea25f31aaa61be53fcb42ce86e9f0e5df6f6dac4c3eee62ac846b0b83a5cfcbe78315175a4961",
  )
  assertEquals(
    bytesToHex(serialize([initRes[4]], cipher)),
    "988f3d473186634e41478dc4527cf240e64de23a763037454d39a876862ebc617738ba6c458142e3746b01eab58ca8d7",
  )
  assertEquals(
    bytesToHex(serialize([initRes[5]], cipher)),
    "2f18dd269c11c512256a9d1d57e61a7d2de6ebcf41cac3053f37afedc4e650a9",
  )
  assertEquals(
    bytesToHex(proof),
    "89e4ab0c160880e0c2f12a754b9c051ed7f5fccfee3d5cbbb62e1239709196c7" +
      "37fff4303054660f8fcd08267a5de668a2e395ebe8866bdcb0dff9786d7014fa" +
      "5e3c8cf7b41f8d7510e27d307f18032f6b788e200b9d6509f40ce1d2f962ceed" +
      "b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57" +
      "e209b584e8fe894bcc964117bf3521b43d8e2eb59ce31f34d68b39f05bb2c625" +
      "e4de5e61e95ff38bfd62ab07105d016414b45b01625c69965ad3c8a933e7b25d" +
      "93daeb777302b966079827a99178240e6c3f13b7db2fb1f14790940e239d775a" +
      "b32f539bdf9f9b582b250b05882996832652f7f5d3b6e04744c73ada1702d679" +
      "1940ccbd75e719537f7ace6ee817298d",
  )

  const verification = verify(
    pkBytes,
    proof,
    generators,
    headerBytes,
    presentationHeaderBytes,
    disclosedMessages,
    disclosedIndexes,
    apiId,
    cipher,
  )
  assert(verification)
})

/**
 * Valid proof for multiple messages, all disclosed.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-valid-multi-message-all-mes
 */
Deno.test("shake-256 proof for multiple message, all disclosed", () => {
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
  const presentationHeaderBytes = hexToBytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")

  const pkBytes = hexToBytes(
    "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
      "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
      "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
  )
  const signatureBytes = hexToBytes(
    "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08" +
      "faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67" +
      "fb7d3253e1e2acbcf90ef59a6911931e",
  )

  const r1 = os2ip(hexToBytes("1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881"))
  const r2 = os2ip(hexToBytes("25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd"))
  const eTilde = os2ip(hexToBytes("5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c"))
  const r1Tilde = os2ip(hexToBytes("3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58"))
  const r3Tilde = os2ip(hexToBytes("016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2"))

  const cipher = BLS12_381_SHAKE_256
  const randoms = [r1, r2, eTilde, r1Tilde, r3Tilde]
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(11, apiId, cipher)
  const [a, e] = octetsToSignature(signatureBytes, cipher)
  const msgs = messagesToScalars([msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10], apiId, cipher)

  const disclosedIndexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  const undisclosedIndexes: Array<number> = []
  const disclosedMessages = msgs.filter((_, i) => disclosedIndexes.includes(i))
  const undisclosedMessages = msgs.filter((_, i) => undisclosedIndexes.includes(i))

  const initRes = init(pkBytes, [a, e], generators, randoms, headerBytes, msgs, undisclosedIndexes, apiId, cipher)
  const c = challenge(initRes, disclosedMessages, disclosedIndexes, presentationHeaderBytes, apiId, cipher)
  const proof = finalize(initRes, c, e, randoms, undisclosedMessages, cipher)

  assertEquals(
    bytesToHex(serialize([initRes[3]], cipher)),
    "8890adfc78da24768d59dbfdb3f380e2793e9018b20c23e9ba05baa60f1b21456bc047a5d27049dab5dc6a94696ce711",
  )
  assertEquals(
    bytesToHex(serialize([initRes[4]], cipher)),
    "a49f953636d3651a3ae6fe45a99a2e4fec079eef3be8b8a6a4ba70885d7e028642f7224e9f451529915c88a7edc59fbe",
  )
  assertEquals(
    bytesToHex(serialize([initRes[5]], cipher)),
    "6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b",
  )
  assertEquals(
    bytesToHex(proof),
    "91b0f598268c57b67bc9e55327c3c2b9b1654be89a0cf963ab392fa9e1637c56" +
      "5241d71fd6d7bbd7dfe243de85a9bac8b7461575c1e13b5055fed0b51fd0ec14" +
      "33096607755b2f2f9ba6dc614dfa456916ca0d7fc6482b39c679cfb747a50ea1" +
      "b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8" +
      "fbdf45cd19fde45038bb310d5135f5205fc550b077e381fb3a3543dca31a0d8b" +
      "ba97bc0b660a5aa239eb74921e184aa3035fa01eaba32f52029319ec3df4fa4a" +
      "4f716edb31a6ce19a19dbb971380099345070bd0fdeecf7c4774a33e0a116e06" +
      "9d5e215992fb637984802066dee6919146ae50b70ea52332dfe57f6e05c66e99" +
      "f1764d8b890d121d65bfcc2984886ee0",
  )

  const verification = verify(
    pkBytes,
    proof,
    generators,
    headerBytes,
    presentationHeaderBytes,
    disclosedMessages,
    disclosedIndexes,
    apiId,
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
  const presentationHeaderBytes = hexToBytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")

  const pkBytes = hexToBytes(
    "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
      "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
      "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
  )
  const signatureBytes = hexToBytes(
    "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08" +
      "faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67" +
      "fb7d3253e1e2acbcf90ef59a6911931e",
  )

  const r1 = os2ip(hexToBytes("5ee9426ae206e3a127eb53c79044bc9ed1b71354f8354b01bf410a02220be7d0"))
  const r2 = os2ip(hexToBytes("280d4fcc38376193ffc777b68459ed7ba897e2857f938581acf95ae5a68988f3"))
  const eTilde = os2ip(hexToBytes("39966b00042fc43906297d692ebb41de08e36aada8d9504d4e0ae02ad59e9230"))
  const r1Tilde = os2ip(hexToBytes("61f5c273999b0b50be8f84d2380eb9220fc5a88afe144efc4007545f0ab9c089"))
  const r3Tilde = os2ip(hexToBytes("63af117e0c8b7d2f1f3e375fcf5d9430e136ff0f7e879423e49dadc401a50089"))
  const mTildes = [
    os2ip(hexToBytes("020b83ca2ab319cba0744d6d58da75ac3dfb6ba682bfce2587c5a6d86a4e4e7b")),
    os2ip(hexToBytes("5bf565343611c08f83e4420e8b1577ace8cc4df5d5303aeb3c4e425f1080f836")),
    os2ip(hexToBytes("049d77949af1192534da28975f76d4f211315dce1e36f93ffcf2a555de516b28")),
    os2ip(hexToBytes("407e5a952f145de7da53533de8366bbd2e0c854721a204f03906dc82fde10f48")),
    os2ip(hexToBytes("1c925d9052849edddcf04d5f1f0d4ff183a66b66eb820f59b675aee121cfc63c")),
    os2ip(hexToBytes("07d7c41b02158a9c5eac212ed6d7c2cddeb8e38baea6e93e1a00b2e83e2a0995")),
  ]

  const cipher = BLS12_381_SHAKE_256
  const randoms = [r1, r2, eTilde, r1Tilde, r3Tilde, ...mTildes]
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(11, apiId, cipher)
  const [a, e] = octetsToSignature(signatureBytes, cipher)
  const msgs = messagesToScalars([msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10], apiId, cipher)

  const disclosedIndexes = [0, 2, 4, 6]
  const undisclosedIndexes = [1, 3, 5, 7, 8, 9]
  const disclosedMessages = msgs.filter((_, i) => disclosedIndexes.includes(i))
  const undisclosedMessages = msgs.filter((_, i) => undisclosedIndexes.includes(i))

  const initRes = init(pkBytes, [a, e], generators, randoms, headerBytes, msgs, undisclosedIndexes, apiId, cipher)
  const c = challenge(initRes, disclosedMessages, disclosedIndexes, presentationHeaderBytes, apiId, cipher)
  const proof = finalize(initRes, c, e, randoms, undisclosedMessages, cipher)

  assertEquals(
    bytesToHex(serialize([initRes[3]], cipher)),
    "8b497dd4dcdcf7eb58c9b43e57e06bcea3468a223ae2fc015d7a86506a952d68055e73f5a5847e58f133ea154256d0da",
  )
  assertEquals(
    bytesToHex(serialize([initRes[4]], cipher)),
    "8655584d3da1313f881f48c239384a5623d2d292f08dae7ac1d8129c19a02a89b82fa45de3f6c2c439510fce5919656f",
  )
  assertEquals(
    bytesToHex(serialize([initRes[5]], cipher)),
    "6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b",
  )
  assertEquals(
    bytesToHex(proof),
    "b1f8bf99a11c39f04e2a032183c1ead12956ad322dd06799c50f20fb8cf6b0ac" +
      "279210ef5a2920a7be3ec2aa0911ace7b96811a98f3c1cceba4a2147ae763b3b" +
      "a036f47bc21c39179f2b395e0ab1ac49017ea5b27848547bedd27be481c1dfc0" +
      "b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595" +
      "ea1b13330615011050a0dfcffdb21af356dd39bf8bcbfd41bf95d913f4c9b297" +
      "9e1ed2ca10ac7e881bb6a271722549681e398d29e9ba4eac8848b168eddd5e4a" +
      "cec7df4103e2ed165e6e32edc80f0a3b28c36fb39ca19b4b8acee570deadba2d" +
      "a9ec20d1f236b571e0d4c2ea3b826fe924175ed4dfffbf18a9cfa98546c241ef" +
      "b9164c444d970e8c89849bc8601e96cf228fdefe38ab3b7e289cac859e68d9cb" +
      "b0e648faf692b27df5ff6539c30da17e5444a65143de02ca64cee7b0823be658" +
      "65cdc310be038ec6b594b99280072ae067bad1117b0ff3201a5506a8533b925c" +
      "7ffae9cdb64558857db0ac5f5e0f18e750ae77ec9cf35263474fef3f78138c7a" +
      "1ef5cfbc878975458239824fad3ce05326ba3969b1f5451bd82bd1f8075f3d32" +
      "ece2d61d89a064ab4804c3c892d651d11bc325464a71cd7aacc2d956a811aaff" +
      "13ea4c35cef7842b656e8ba4758e7558",
  )

  const verification = verify(
    pkBytes,
    proof,
    generators,
    headerBytes,
    presentationHeaderBytes,
    disclosedMessages,
    disclosedIndexes,
    apiId,
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

  const headerBytes = undefined
  const presentationHeaderBytes = hexToBytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")

  const pkBytes = hexToBytes(
    "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
      "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
      "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
  )
  const signatureBytes = hexToBytes(
    "88beeb970f803160d3058eacde505207c576a8c9e4e5dc7c5249cbcf2a046c15" +
      "f8df047031eef3436e04b779d92a9cdb1fe4c6cc035ba1634f1740f9dd49816d" +
      "3ca745ecbe39f655ea61fb700137fded",
  )

  const r1 = os2ip(hexToBytes("5ee9426ae206e3a127eb53c79044bc9ed1b71354f8354b01bf410a02220be7d0"))
  const r2 = os2ip(hexToBytes("280d4fcc38376193ffc777b68459ed7ba897e2857f938581acf95ae5a68988f3"))
  const eTilde = os2ip(hexToBytes("39966b00042fc43906297d692ebb41de08e36aada8d9504d4e0ae02ad59e9230"))
  const r1Tilde = os2ip(hexToBytes("61f5c273999b0b50be8f84d2380eb9220fc5a88afe144efc4007545f0ab9c089"))
  const r3Tilde = os2ip(hexToBytes("63af117e0c8b7d2f1f3e375fcf5d9430e136ff0f7e879423e49dadc401a50089"))
  const mTildes = [
    os2ip(hexToBytes("020b83ca2ab319cba0744d6d58da75ac3dfb6ba682bfce2587c5a6d86a4e4e7b")),
    os2ip(hexToBytes("5bf565343611c08f83e4420e8b1577ace8cc4df5d5303aeb3c4e425f1080f836")),
    os2ip(hexToBytes("049d77949af1192534da28975f76d4f211315dce1e36f93ffcf2a555de516b28")),
    os2ip(hexToBytes("407e5a952f145de7da53533de8366bbd2e0c854721a204f03906dc82fde10f48")),
    os2ip(hexToBytes("1c925d9052849edddcf04d5f1f0d4ff183a66b66eb820f59b675aee121cfc63c")),
    os2ip(hexToBytes("07d7c41b02158a9c5eac212ed6d7c2cddeb8e38baea6e93e1a00b2e83e2a0995")),
  ]

  const cipher = BLS12_381_SHAKE_256
  const randoms = [r1, r2, eTilde, r1Tilde, r3Tilde, ...mTildes]
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(11, apiId, cipher)
  const [a, e] = octetsToSignature(signatureBytes, cipher)
  const msgs = messagesToScalars([msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10], apiId, cipher)

  const disclosedIndexes = [0, 2, 4, 6]
  const undisclosedIndexes = [1, 3, 5, 7, 8, 9]
  const disclosedMessages = msgs.filter((_, i) => disclosedIndexes.includes(i))
  const undisclosedMessages = msgs.filter((_, i) => undisclosedIndexes.includes(i))

  const initRes = init(pkBytes, [a, e], generators, randoms, headerBytes, msgs, undisclosedIndexes, apiId, cipher)
  const c = challenge(initRes, disclosedMessages, disclosedIndexes, presentationHeaderBytes, apiId, cipher)
  const proof = finalize(initRes, c, e, randoms, undisclosedMessages, cipher)

  assertEquals(
    bytesToHex(serialize([initRes[3]], cipher)),
    "a5405cc2c5965dda18714ab35f4d4a7ae4024f388fa7a5ba71202d4455b50b316ec37b360659e3012234562fa8989980",
  )
  assertEquals(
    bytesToHex(serialize([initRes[4]], cipher)),
    "9827a40454cdc90a70e9c927f097019dbdd84768babb10ebcb460c2d918e1ce1c0512bf2cc49ed7ec476dfcde7a6a10c",
  )
  assertEquals(
    bytesToHex(serialize([initRes[5]], cipher)),
    "333d8686761cff65a3a2ef20bfa217d37bdf19105e87c210e9ce64ea1210a157",
  )
  assertEquals(
    bytesToHex(proof),
    "8ac336eea1d278656372d9914483c3d3b3069dfa4a7862293ac021dfeeebca93" +
      "cadd7eb2b818f7b89719cdeffa5aa85989a7d691be11b1929a2bf089bfe9f2ad" +
      "c2c06788edc30585546efb74877f34ad91f0d6923b4ed7a53c49051dda8d056a" +
      "95644ee738810772d90c1033f1dfe45c0b1b453d131170aafa8a99f812f3b90a" +
      "5d1d9e6bd05a4dee6a50dd277ffc646f2429372f3ad9d5946ffeb53f24d41ffc" +
      "c83c32cbb68afc9b6e0b64eebd24c69c6a7bd3bca8a6394ed8ae315abd555a69" +
      "96f34d9da7680447947b3f35f54c38b562e990ee4d17a21569af4fc02f2991e6" +
      "db78cc32d3ef9f6069fc5c2d47c8d8ff116dfb8a59641641961b854427f67649" +
      "df14ab6e63f2d0d2a0cba2b2e1e835d20cd45e41f274532e9d50f31a690e5fef" +
      "1c1456b65c668b80d8ec17b09bd5fb3b2c4edd6d6f5f790a5d6da22eb9a1aa21" +
      "96d1a607f3c753813ba2bc6ece15d35263218fc7667c5f0fabfffe74745a8000" +
      "e0415c8dafd5654ce6850ac2c6485d02433fdaebd9993f8b86a2eebb3beb10b4" +
      "cc7735330384a3f4dfd4d5b21998ad0227b37e736cf9c144a0386f28cccf27a0" +
      "1e50aab45dda8275eb877728e77d2055309dba8c6604e7cff0d2c46ce6026b8e" +
      "232c192955f909da6e47c2130c7e3f4f",
  )

  const verification = verify(
    pkBytes,
    proof,
    generators,
    headerBytes,
    presentationHeaderBytes,
    disclosedMessages,
    disclosedIndexes,
    apiId,
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
  const presentationHeaderBytes = undefined

  const pkBytes = hexToBytes(
    "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
      "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
      "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5",
  )
  const signatureBytes = hexToBytes(
    "956a3427b1b8e3642e60e6a7990b67626811adeec7a0a6cb4f770cdd7c20cf08" +
      "faabb913ac94d18e1e92832e924cb6e202912b624261fc6c59b0fea801547f67" +
      "fb7d3253e1e2acbcf90ef59a6911931e",
  )

  const r1 = os2ip(hexToBytes("5ee9426ae206e3a127eb53c79044bc9ed1b71354f8354b01bf410a02220be7d0"))
  const r2 = os2ip(hexToBytes("280d4fcc38376193ffc777b68459ed7ba897e2857f938581acf95ae5a68988f3"))
  const eTilde = os2ip(hexToBytes("39966b00042fc43906297d692ebb41de08e36aada8d9504d4e0ae02ad59e9230"))
  const r1Tilde = os2ip(hexToBytes("61f5c273999b0b50be8f84d2380eb9220fc5a88afe144efc4007545f0ab9c089"))
  const r3Tilde = os2ip(hexToBytes("63af117e0c8b7d2f1f3e375fcf5d9430e136ff0f7e879423e49dadc401a50089"))
  const mTildes = [
    os2ip(hexToBytes("020b83ca2ab319cba0744d6d58da75ac3dfb6ba682bfce2587c5a6d86a4e4e7b")),
    os2ip(hexToBytes("5bf565343611c08f83e4420e8b1577ace8cc4df5d5303aeb3c4e425f1080f836")),
    os2ip(hexToBytes("049d77949af1192534da28975f76d4f211315dce1e36f93ffcf2a555de516b28")),
    os2ip(hexToBytes("407e5a952f145de7da53533de8366bbd2e0c854721a204f03906dc82fde10f48")),
    os2ip(hexToBytes("1c925d9052849edddcf04d5f1f0d4ff183a66b66eb820f59b675aee121cfc63c")),
    os2ip(hexToBytes("07d7c41b02158a9c5eac212ed6d7c2cddeb8e38baea6e93e1a00b2e83e2a0995")),
  ]

  const cipher = BLS12_381_SHAKE_256
  const randoms = [r1, r2, eTilde, r1Tilde, r3Tilde, ...mTildes]
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(11, apiId, cipher)
  const [a, e] = octetsToSignature(signatureBytes, cipher)
  const msgs = messagesToScalars([msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10], apiId, cipher)

  const disclosedIndexes = [0, 2, 4, 6]
  const undisclosedIndexes = [1, 3, 5, 7, 8, 9]
  const disclosedMessages = msgs.filter((_, i) => disclosedIndexes.includes(i))
  const undisclosedMessages = msgs.filter((_, i) => undisclosedIndexes.includes(i))

  const initRes = init(pkBytes, [a, e], generators, randoms, headerBytes, msgs, undisclosedIndexes, apiId, cipher)
  const c = challenge(initRes, disclosedMessages, disclosedIndexes, presentationHeaderBytes, apiId, cipher)
  const proof = finalize(initRes, c, e, randoms, undisclosedMessages, cipher)

  assertEquals(
    bytesToHex(serialize([initRes[3]], cipher)),
    "8b497dd4dcdcf7eb58c9b43e57e06bcea3468a223ae2fc015d7a86506a952d68055e73f5a5847e58f133ea154256d0da",
  )
  assertEquals(
    bytesToHex(serialize([initRes[4]], cipher)),
    "8655584d3da1313f881f48c239384a5623d2d292f08dae7ac1d8129c19a02a89b82fa45de3f6c2c439510fce5919656f",
  )
  assertEquals(
    bytesToHex(serialize([initRes[5]], cipher)),
    "6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b",
  )
  assertEquals(
    bytesToHex(proof),
    "b1f8bf99a11c39f04e2a032183c1ead12956ad322dd06799c50f20fb8cf6b0ac" +
      "279210ef5a2920a7be3ec2aa0911ace7b96811a98f3c1cceba4a2147ae763b3b" +
      "a036f47bc21c39179f2b395e0ab1ac49017ea5b27848547bedd27be481c1dfc0" +
      "b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595" +
      "ea1b13330615011050a0dfcffdb21af33fda9e14ba4cc0fcad8015bce3fecc47" +
      "04799bef9924ab19688fc04f760c4da35017072a3e295788eff1b0dc2311bb19" +
      "9c186f86ea0540379d5a2ac8b7bd02d22487f2acc0e299115e16097b970badea" +
      "802752a6fcb56cfbbcc2569916a8d3fe6d2d0fb1ae801cfc5ce056699adf23e3" +
      "cd16b1fdf197deac099ab093da049a5b4451d038c71b7cc69e8390967594f677" +
      "7a855c7f5d301f0f0573211ac85e2e165ea196f78c33f54092645a51341b777f" +
      "0f5342301991f3da276c04b0224f7308090ae0b290d428a0570a71605a27977e" +
      "7daf01d42dfbdcec252686c3060a73d81f6e151e23e3df2473b322da389f15a5" +
      "5cb2cd8a2bf29ef0d83d4876117735465fae956d8df56ec9eb0e4748ad3ef558" +
      "7797368c51a0ccd67eb6da38602a1c2d4fd411214efc6932334ba0bcbf562626" +
      "e7c0e1ae0db912c28d99f194fa3cd3a2",
  )

  const verification = verify(
    pkBytes,
    proof,
    generators,
    headerBytes,
    presentationHeaderBytes,
    disclosedMessages,
    disclosedIndexes,
    apiId,
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
  const cipher = BLS12_381_SHA_256
  const headerBytes = hexToBytes("11223344556677889900aabbccddeeff")
  const presentationHeaderBytes = hexToBytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
  const msgBytes = hexToBytes("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02")
  const pkBytes = hexToBytes(
    "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
      "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
      "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
  )
  const signatureBytes = hexToBytes(
    "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da525" +
      "3aa8458317cca0eae615690d55b1f27164657dcafee1d5c1973947aa70e2cfbb" +
      "4c892340be5969920d0916067b4565a0",
  )
  const r1 = os2ip(hexToBytes("60ca409f6b0563f687fc471c63d2819f446f39c23bb540925d9d4254ac58f337"))
  const r2 = os2ip(hexToBytes("2ceff4982de0c913090f75f081df5ec594c310bb48c17cfdaab5332a682ef811"))
  const eTilde = os2ip(hexToBytes("6101c4404895f3dff87ab39c34cb995af07e7139e6b3847180ffdd1bc8c313cd"))
  const r1Tilde = os2ip(hexToBytes("0dfcffd97a6ecdebef3c9c114b99d7a030c998d938905f357df62822dee072e8"))
  const r3Tilde = os2ip(hexToBytes("639e3417007d38e5d34ba8c511e836768ddc2669fdd3faff5c14ad27ac2b2da1"))

  const [a, e] = octetsToSignature(signatureBytes, cipher)
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(2, apiId, cipher)
  const randoms = [r1, r2, eTilde, r1Tilde, r3Tilde]
  const msgs = messagesToScalars([msgBytes], apiId, cipher)

  const disclosedIndexes: Array<number> = [0]
  const undisclosedIndexes: Array<number> = []
  const disclosedMessages = msgs.filter((_, i) => disclosedIndexes.includes(i))
  const undisclosedMessages = msgs.filter((_, i) => undisclosedIndexes.includes(i))

  const initRes = init(pkBytes, [a, e], generators, randoms, headerBytes, msgs, undisclosedIndexes, apiId, cipher)
  const c = challenge(initRes, disclosedMessages, disclosedIndexes, presentationHeaderBytes, apiId, cipher)
  const proof = finalize(initRes, c, e, randoms, undisclosedMessages, cipher)

  assertEquals(
    bytesToHex(serialize([initRes[3]], cipher)),
    "a862fa5d3ab4c264c22b8a02636fd4030e8b14ac20dee14e08fdb6cfc445432c08abb49ec111c1eb9d90abef50134a60",
  )
  assertEquals(
    bytesToHex(serialize([initRes[4]], cipher)),
    "ab9543a6b04303e997621d3d5cbd85924e7e69da498a2a9e9d3a8b01f39259c9c5920bd530de1d3b0afb99eb0c549d5a",
  )
  assertEquals(
    bytesToHex(serialize([initRes[5]], cipher)),
    "25d57fab92a8274c68fde5c3f16d4b275e4a156f211ae34b3ab32fbaf506ed5c",
  )
  assertEquals(
    bytesToHex(proof),
    "94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104" +
      "ef2b2fcf72df0215eeaf69262ffe8194a19fab31a82ddbe06908985abc4c9825" +
      "788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f33e0aad" +
      "aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32" +
      "c54db7587b5ee3ab665fbd37b506830a49f21d592f5e634f47cee05a025a2f8f" +
      "94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d64080678dbf2" +
      "9417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e" +
      "940cfeaa5e72104576a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d45" +
      "5feeb04426193c57086c9b6d397d9418",
  )

  const verification = verify(
    pkBytes,
    proof,
    generators,
    headerBytes,
    presentationHeaderBytes,
    disclosedMessages,
    disclosedIndexes,
    apiId,
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
  const presentationHeaderBytes = hexToBytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")

  const pkBytes = hexToBytes(
    "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
      "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
      "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
  )
  const signatureBytes = hexToBytes(
    "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146" +
      "3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36" +
      "32078557b2ace7d44caed846e1a0a1e8",
  )

  const r1 = os2ip(hexToBytes("60ca409f6b0563f687fc471c63d2819f446f39c23bb540925d9d4254ac58f337"))
  const r2 = os2ip(hexToBytes("2ceff4982de0c913090f75f081df5ec594c310bb48c17cfdaab5332a682ef811"))
  const eTilde = os2ip(hexToBytes("6101c4404895f3dff87ab39c34cb995af07e7139e6b3847180ffdd1bc8c313cd"))
  const r1Tilde = os2ip(hexToBytes("0dfcffd97a6ecdebef3c9c114b99d7a030c998d938905f357df62822dee072e8"))
  const r3Tilde = os2ip(hexToBytes("639e3417007d38e5d34ba8c511e836768ddc2669fdd3faff5c14ad27ac2b2da1"))

  const cipher = BLS12_381_SHA_256
  const randoms = [r1, r2, eTilde, r1Tilde, r3Tilde]
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(11, apiId, cipher)
  const [a, e] = octetsToSignature(signatureBytes, cipher)
  const msgs = messagesToScalars([msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10], apiId, cipher)

  const disclosedIndexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  const undisclosedIndexes: Array<number> = []
  const disclosedMessages = msgs.filter((_, i) => disclosedIndexes.includes(i))
  const undisclosedMessages = msgs.filter((_, i) => undisclosedIndexes.includes(i))

  const initRes = init(pkBytes, [a, e], generators, randoms, headerBytes, msgs, undisclosedIndexes, apiId, cipher)
  const c = challenge(initRes, disclosedMessages, disclosedIndexes, presentationHeaderBytes, apiId, cipher)
  const proof = finalize(initRes, c, e, randoms, undisclosedMessages, cipher)

  assertEquals(
    bytesToHex(serialize([initRes[3]], cipher)),
    "9881efa96b2411626d490e399eb1c06badf23c2c0760bd403f50f45a6b470c5a9dbeef53a27916f2f165085a3878f1f4",
  )
  assertEquals(
    bytesToHex(serialize([initRes[4]], cipher)),
    "b9f8cf9271d10a04ae7116ad021f4b69c435d20a5af10ddd8f5b1ec6b9b8b91605aca76a140241784b7f161e21dfc3e7",
  )
  assertEquals(
    bytesToHex(serialize([initRes[5]], cipher)),
    "6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47",
  )
  assertEquals(
    bytesToHex(proof),
    "b1f468aec2001c4f54cb56f707c6222a43e5803a25b2253e67b2210ab2ef9eab" +
      "52db2d4b379935c4823281eaf767fd37b08ce80dc65de8f9769d27099ae649ad" +
      "4c9b4bd2cc23edcba52073a298087d2495e6d57aaae051ef741adf1cbce65c64" +
      "a73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef" +
      "47855480b7b30b5e4052c92a4360110c67327365763f5aa9fb85ddcbc2975449" +
      "b8c03db1216ca66b310f07d0ccf12ab460cdc6003b677fed36d0a23d0818a9d4" +
      "d098d44f749e91008cf50e8567ef936704c8277b7710f41ab7e6e16408ab520e" +
      "dc290f9801349aee7b7b4e318e6a76e028e1dea911e2e7baec6a6a174da1a223" +
      "62717fbae1cd961d7bf4adce1d31c2ab",
  )

  const verification = verify(
    pkBytes,
    proof,
    generators,
    headerBytes,
    presentationHeaderBytes,
    disclosedMessages,
    disclosedIndexes,
    apiId,
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
  const presentationHeaderBytes = hexToBytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")

  const pkBytes = hexToBytes(
    "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
      "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
      "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c",
  )
  const signatureBytes = hexToBytes(
    "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e146" +
      "3e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed36" +
      "32078557b2ace7d44caed846e1a0a1e8",
  )

  const r1 = os2ip(hexToBytes("44679831fe60eca50938ef0e812e2a9284ad7971b6932a38c7303538b712e457"))
  const r2 = os2ip(hexToBytes("6481692f89086cce11779e847ff884db8eebb85a13e81b2d0c79d6c1062069d8"))
  const eTilde = os2ip(hexToBytes("721ce4c4c148a1d5826f326af6fd6ac2844f29533ba4127c3a43d222d51b7081"))
  const r1Tilde = os2ip(hexToBytes("1ecfaf5a079b0504b00a1f0d6fe8857291dd798291d7ad7454b398114393f37f"))
  const r3Tilde = os2ip(hexToBytes("0a4b3d59b34707bb9999bc6e2a6d382a2d2e214bff36ecd88639a14124b1622e"))
  const mTildes = [
    os2ip(hexToBytes("7217411a9e329c7a5705e8db552274646e2949d62c288d7537dd62bc284715e4")),
    os2ip(hexToBytes("67d4d43660746759f598caac106a2b5f58ccd1c3eefaec31841a4f77d2548870")),
    os2ip(hexToBytes("715d965b1c3912d20505b381470ff1a528700b673e50ba89fd287e13171cc137")),
    os2ip(hexToBytes("4d3281a149674e58c9040fc7a10dd92cb9c7f76f6f0815a1afc3b09d74b92fe4")),
    os2ip(hexToBytes("438feebaa5894ca0da49992df2c97d872bf153eab07e08ff73b28131c46ff415")),
    os2ip(hexToBytes("602b723c8bbaec1b057d70f18269ae5e6de6197a5884967b03b933fa80006121")),
  ]

  const cipher = BLS12_381_SHA_256
  const randoms = [r1, r2, eTilde, r1Tilde, r3Tilde, ...mTildes]
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(11, apiId, cipher)
  const [a, e] = octetsToSignature(signatureBytes, cipher)
  const msgs = messagesToScalars([msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10], apiId, cipher)

  const disclosedIndexes = [0, 2, 4, 6]
  const undisclosedIndexes = [1, 3, 5, 7, 8, 9]
  const disclosedMessages = msgs.filter((_, i) => disclosedIndexes.includes(i))
  const undisclosedMessages = msgs.filter((_, i) => undisclosedIndexes.includes(i))

  const initRes = init(pkBytes, [a, e], generators, randoms, headerBytes, msgs, undisclosedIndexes, apiId, cipher)
  const c = challenge(initRes, disclosedMessages, disclosedIndexes, presentationHeaderBytes, apiId, cipher)
  const proof = finalize(initRes, c, e, randoms, undisclosedMessages, cipher)

  assertEquals(
    bytesToHex(serialize([initRes[3]], cipher)),
    "84719c2b5bb275ee74913dbf95fb9054f690c8e4035f1259e184e9024544bc4bbea9c244e7897f9db7c82b7b14b27d28",
  )
  assertEquals(
    bytesToHex(serialize([initRes[4]], cipher)),
    "8f5f191c956aefd5c960e57d2dfbab6761eb0ebc5efdba1aca1403dcc19e05296b16c9feb7636cb4ef2a360c5a148483",
  )
  assertEquals(
    bytesToHex(serialize([initRes[5]], cipher)),
    "6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47",
  )
  assertEquals(
    bytesToHex(proof),
    "a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d" +
      "340394223a5397a3011b1c340ebc415199462ba6f31106d8a6da8b513b37a47a" +
      "fe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d452f" +
      "897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436af" +
      "d24457658acbaba5ddac2e693ac481356918cd38025d86b28650e909defe9604" +
      "a7259f44386b861608be742af7775a2e71a6070e5836f5f54dc43c60096834a5" +
      "b6da295bf8f081f72b7cdf7f3b4347fb3ff19edaa9e74055c8ba46dbcb7594fb" +
      "2b06633bb5324192eb9be91be0d33e453b4d3127459de59a5e2193c900816f04" +
      "9a02cb9127dac894418105fa1641d5a206ec9c42177af9316f43341744147827" +
      "6ca0303da8f941bf2e0222a43251cf5c2bf6eac1961890aa740534e519c1767e" +
      "1223392a3a286b0f4d91f7f25217a7862b8fcc1810cdcfddde2a01c80fcc90b6" +
      "32585fec12dc4ae8fea1918e9ddeb9414623a457e88f53f545841f9d5dcb1f8e" +
      "160d1560770aa79d65e2eca8edeaecb73fb7e995608b820c4a64de6313a370ba" +
      "05dc25ed7c1d185192084963652f2870341bdaa4b1a37f8c06348f38a4f80c5a" +
      "2650a21d59f09e8305dcd3fc3ac30e2a",
  )

  const verification = verify(
    pkBytes,
    proof,
    generators,
    headerBytes,
    presentationHeaderBytes,
    disclosedMessages,
    disclosedIndexes,
    apiId,
    cipher,
  )
  assert(verification)
})
