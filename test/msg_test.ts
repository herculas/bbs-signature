import { assertEquals } from "@std/assert/equals"
import { BLS12_381_SHAKE_256 } from "../src/suite/ciphers.ts"
import { bytesToHex, concatenate, hexToBytes, i2osp } from "../src/utils/format.ts"
import { createGenerators, messagesToScalars } from "../src/utils/interface.ts"

Deno.test("map messages to scalars", () => {
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

  const apiId = concatenate(BLS12_381_SHAKE_256.id, new TextEncoder().encode("H2G_HM2S_"))

  const scalars = messagesToScalars(
    [msg_1, msg_2, msg_3, msg_4, msg_5, msg_6, msg_7, msg_8, msg_9, msg_10],
    apiId,
    BLS12_381_SHAKE_256,
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

Deno.test("message generators", () => {
  const apiId = concatenate(BLS12_381_SHAKE_256.id, new TextEncoder().encode("H2G_HM2S_"))
  const generators = createGenerators(11, apiId, BLS12_381_SHAKE_256)

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
