import { assertEquals } from "@std/assert/equals"

import { BLS12_381_SHA_256, BLS12_381_SHAKE_256 } from "../src/suite/ciphers.ts"
import { bytesToHex, concatenate, hexToBytes, i2osp } from "../src/utils/format.ts"
import { createGenerators, messagesToScalars } from "../src/utils/interface.ts"

/**
 * Test for mapping messages in hex format to scalars, in BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-map-messages-to-scalars
 */
Deno.test("shake-256 map messages to scalars", () => {
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

  const cipher = BLS12_381_SHAKE_256
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))

  const scalars = messagesToScalars(
    [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10],
    apiId,
    cipher,
  )

  const scalar_1 = bytesToHex(i2osp(scalars[0], 32))
  const scalar_2 = bytesToHex(i2osp(scalars[1], 32))
  const scalar_3 = bytesToHex(i2osp(scalars[2], 32))
  const scalar_4 = bytesToHex(i2osp(scalars[3], 32))
  const scalar_5 = bytesToHex(i2osp(scalars[4], 32))
  const scalar_6 = bytesToHex(i2osp(scalars[5], 32))
  const scalar_7 = bytesToHex(i2osp(scalars[6], 32))
  const scalar_8 = bytesToHex(i2osp(scalars[7], 32))
  const scalar_9 = bytesToHex(i2osp(scalars[8], 32))
  const scalar_10 = bytesToHex(i2osp(scalars[9], 32))

  assertEquals(scalar_1, "1e0dea6c9ea8543731d331a0ab5f64954c188542b33c5bbc8ae5b3a830f2d99f")
  assertEquals(scalar_2, "3918a40fb277b4c796805d1371931e08a314a8bf8200a92463c06054d2c56a9f")
  assertEquals(scalar_3, "6642b981edf862adf34214d933c5d042bfa8f7ef343165c325131e2ffa32fa94")
  assertEquals(scalar_4, "33c021236956a2006f547e22ff8790c9d2d40c11770c18cce6037786c6f23512")
  assertEquals(scalar_5, "52b249313abbe323e7d84230550f448d99edfb6529dec8c4e783dbd6dd2a8471")
  assertEquals(scalar_6, "2a50bdcbe7299e47e1046100aadffe35b4247bf3f059d525f921537484dd54fc")
  assertEquals(scalar_7, "0e92550915e275f8cfd6da5e08e334d8ef46797ee28fa29de40a1ebccd9d95d3")
  assertEquals(scalar_8, "4c28f612e6c6f82f51f95e1e4faaf597547f93f6689827a6dcda3cb94971d356")
  assertEquals(scalar_9, "1db51bedc825b85efe1dab3e3ab0274fa82bbd39732be3459525faf70f197650")
  assertEquals(scalar_10, "27878da72f7775e709bb693d81b819dc4e9fa60711f4ea927740e40073489e78")
})

/**
 * Test for generating G1 generators, in BLS12-381-SHAKE-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-message-generators
 */
Deno.test("shake-256 message generators", () => {
  const cipher = BLS12_381_SHAKE_256
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(11, apiId, cipher)

  const q_1 = bytesToHex(generators[0].toRawBytes())
  const h_1 = bytesToHex(generators[1].toRawBytes())
  const h_2 = bytesToHex(generators[2].toRawBytes())
  const h_3 = bytesToHex(generators[3].toRawBytes())
  const h_4 = bytesToHex(generators[4].toRawBytes())
  const h_5 = bytesToHex(generators[5].toRawBytes())
  const h_6 = bytesToHex(generators[6].toRawBytes())
  const h_7 = bytesToHex(generators[7].toRawBytes())
  const h_8 = bytesToHex(generators[8].toRawBytes())
  const h_9 = bytesToHex(generators[9].toRawBytes())
  const h_10 = bytesToHex(generators[10].toRawBytes())

  assertEquals(q_1, "a9d40131066399fd41af51d883f4473b0dcd7d028d3d34ef17f3241d204e28507d7ecae032afa1d5490849b7678ec1f8")
  assertEquals(h_1, "903c7ca0b7e78a2017d0baf74103bd00ca8ff9bf429f834f071c75ffe6bfdec6d6dca15417e4ac08ca4ae1e78b7adc0e")
  assertEquals(h_2, "84321f5855bfb6b001f0dfcb47ac9b5cc68f1a4edd20f0ec850e0563b27d2accee6edff1a26b357762fb24e8ddbb6fcb")
  assertEquals(h_3, "b3060dff0d12a32819e08da00e61810676cc9185fdd750e5ef82b1a9798c7d76d63de3b6225d6c9a479d6c21a7c8bf93")
  assertEquals(h_4, "8f1093d1e553cdead3c70ce55b6d664e5d1912cc9edfdd37bf1dad11ca396a0a8bb062092d391ebf8790ea5722413f68")
  assertEquals(h_5, "990824e00b48a68c3d9a308e8c52a57b1bc84d1cf5d3c0f8c6fb6b1230e4e5b8eb752fb374da0b1ef687040024868140")
  assertEquals(h_6, "b86d1c6ab8ce22bc53f625d1ce9796657f18060fcb1893ce8931156ef992fe56856199f8fa6c998e5d855a354a26b0dd")
  assertEquals(h_7, "b4cdd98c5c1e64cb324e0c57954f719d5c5f9e8d991fd8e159b31c8d079c76a67321a30311975c706578d3a0ddc313b7")
  assertEquals(h_8, "8311492d43ec9182a5fc44a75419b09547e311251fe38b6864dc1e706e29446cb3ea4d501634eb13327245fd8a574f77")
  assertEquals(h_9, "ac00b493f92d17837a28d1f5b07991ca5ab9f370ae40d4f9b9f2711749ca200110ce6517dc28400d4ea25dddc146cacc")
  assertEquals(h_10, "965a6c62451d4be6cb175dec39727dc665762673ee42bf0ac13a37a74784fbd61e84e0915277a6f59863b2bb4f5f6005")
})

/**
 * Test for mapping messages in hex format to scalars, in BLS12-381-SHA-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-map-messages-to-scalars-2
 */
Deno.test("sha-256 map messages to scalars", () => {
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

  const cipher = BLS12_381_SHA_256
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))

  const scalars = messagesToScalars(
    [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10],
    apiId,
    cipher,
  )

  const scalar_1 = bytesToHex(i2osp(scalars[0], 32))
  const scalar_2 = bytesToHex(i2osp(scalars[1], 32))
  const scalar_3 = bytesToHex(i2osp(scalars[2], 32))
  const scalar_4 = bytesToHex(i2osp(scalars[3], 32))
  const scalar_5 = bytesToHex(i2osp(scalars[4], 32))
  const scalar_6 = bytesToHex(i2osp(scalars[5], 32))
  const scalar_7 = bytesToHex(i2osp(scalars[6], 32))
  const scalar_8 = bytesToHex(i2osp(scalars[7], 32))
  const scalar_9 = bytesToHex(i2osp(scalars[8], 32))
  const scalar_10 = bytesToHex(i2osp(scalars[9], 32))

  assertEquals(scalar_1, "1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430")
  assertEquals(scalar_2, "154249d503c093ac2df516d4bb88b510d54fd97e8d7121aede420a25d9521952")
  assertEquals(scalar_3, "0c7c4c85cdab32e6fdb0de267b16fa3212733d4e3a3f0d0f751657578b26fe22")
  assertEquals(scalar_4, "4a196deafee5c23f630156ae13be3e46e53b7e39094d22877b8cba7f14640888")
  assertEquals(scalar_5, "34c5ea4f2ba49117015a02c711bb173c11b06b3f1571b88a2952b93d0ed4cf7e")
  assertEquals(scalar_6, "4045b39b83055cd57a4d0203e1660800fabe434004dbdc8730c21ce3f0048b08")
  assertEquals(scalar_7, "064621da4377b6b1d05ecc37cf3b9dfc94b9498d7013dc5c4a82bf3bb1750743")
  assertEquals(scalar_8, "34ac9196ace0a37e147e32319ea9b3d8cc7d21870d3c3ba071246859cca49b02")
  assertEquals(scalar_9, "57eb93f417c43200e9784fa5ea5a59168d3dbc38df707a13bb597c871b2a5f74")
  assertEquals(scalar_10, "08e3afeb2b4f2b5f907924ef42856616e6f2d5f1fb373736db1cca32707a7d16")
})

/**
 * Test for generating G1 generators, in BLS12-381-SHA-256.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07#name-message-generators-2
 */
Deno.test("sha-256 message generators", () => {
  const cipher = BLS12_381_SHA_256
  const apiId = concatenate(cipher.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(11, apiId, cipher)

  const q_1 = bytesToHex(generators[0].toRawBytes())
  const h_1 = bytesToHex(generators[1].toRawBytes())
  const h_2 = bytesToHex(generators[2].toRawBytes())
  const h_3 = bytesToHex(generators[3].toRawBytes())
  const h_4 = bytesToHex(generators[4].toRawBytes())
  const h_5 = bytesToHex(generators[5].toRawBytes())
  const h_6 = bytesToHex(generators[6].toRawBytes())
  const h_7 = bytesToHex(generators[7].toRawBytes())
  const h_8 = bytesToHex(generators[8].toRawBytes())
  const h_9 = bytesToHex(generators[9].toRawBytes())
  const h_10 = bytesToHex(generators[10].toRawBytes())

  assertEquals(q_1, "a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be")
  assertEquals(h_1, "98cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d4")
  assertEquals(h_2, "a31fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a")
  assertEquals(h_3, "b479263445f4d2108965a9086f9d1fdc8cde77d14a91c856769521ad3344754cc5ce90d9bc4c696dffbc9ef1d6ad1b62")
  assertEquals(h_4, "ac0401766d2128d4791d922557c7b4d1ae9a9b508ce266575244a8d6f32110d7b0b7557b77604869633bb49afbe20035")
  assertEquals(h_5, "b95d2898370ebc542857746a316ce32fa5151c31f9b57915e308ee9d1de7db69127d919e984ea0747f5223821b596335")
  assertEquals(h_6, "8f19359ae6ee508157492c06765b7df09e2e5ad591115742f2de9c08572bb2845cbf03fd7e23b7f031ed9c7564e52f39")
  assertEquals(h_7, "abc914abe2926324b2c848e8a411a2b6df18cbe7758db8644145fefb0bf0a2d558a8c9946bd35e00c69d167aadf304c1")
  assertEquals(h_8, "80755b3eb0dd4249cbefd20f177cee88e0761c066b71794825c9997b551f24051c352567ba6c01e57ac75dff763eaa17")
  assertEquals(h_9, "82701eb98070728e1769525e73abff1783cedc364adb20c05c897a62f2ab2927f86f118dcb7819a7b218d8f3fee4bd7f")
  assertEquals(h_10, "a1f229540474f4d6f1134761b92b788128c7ac8dc9b0c52d59493132679673032ac7db3fb3d79b46b13c1c41ee495bca")
})
