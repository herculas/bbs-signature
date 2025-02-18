import { assert } from "@std/assert"

import * as pseudo from "../lib/pseudonym.ts"
import * as CONSTANT from "../lib/constants.ts"

Deno.test("Shake-256 signature for pseudonym, hidden pid value, all messages", () => {
  const cipher = CONSTANT.Cipher.XOF_SHAKE_256
  const header = "11223344556677889900aabbccddeeff"
  const proverNym = "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418"

  const secretKey = "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

  const message0 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const message1 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const message2 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const message3 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const message4 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const message5 = "515ae153e22aae04ad16f759e07237b4"
  const message6 = "d183ddc6e2665aa4e2f088af"
  const message7 = "ac55fb33a75909ed"
  const message8 = "96012096"
  const message9 = ""

  const messages = [
    message0,
    message1,
    message2,
    message3,
    message4,
    message5,
    message6,
    message7,
    message8,
    message9,
  ]
  const committedMessages = new Array<string>()

  const commitmentWithProof = "990c1837a8af86843213e5b12fbfc962efcaf8fd0e5812a6237b91b00a47b5a3" +
    "4714a60b4c365f72b47a4d9b656dde4753a18a8286aca2bf58e8bb9a3d77a3e0" +
    "052aefc427e5e47b666255e53cfcaa7d34d36adc13da01798b8eb041652a57c3" +
    "b595ace54ed5eee43370c1697eb5ce996020d88ca5d811c011cde10c6c07dc2f" +
    "4acbc89bd5652414d5b8823a250ed40b"
  const proverBlindness = "643a0c0bc86a50e0d8c00bfe6c8debd85373597e1aef6cc912838bf7dc376e48"

  const { signature, entropy } = pseudo.sign(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
  const result = pseudo.verify(
    publicKey,
    signature,
    header,
    messages,
    committedMessages,
    proverNym,
    entropy,
    proverBlindness,
    cipher,
  )
  assert(result)
})

Deno.test("Shake-256 proof for pseudonym, multiple messages revealed", () => {
  const cipher = CONSTANT.Cipher.XOF_SHAKE_256

  const header = "11223344556677889900aabbccddeeff"
  const presentationHeader = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501"

  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

  const message0 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const message1 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const message2 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const message3 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const message4 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const message5 = "515ae153e22aae04ad16f759e07237b4"
  const message6 = "d183ddc6e2665aa4e2f088af"
  const message7 = "ac55fb33a75909ed"
  const message8 = "96012096"
  const message9 = ""

  const messages = [
    message0,
    message1,
    message2,
    message3,
    message4,
    message5,
    message6,
    message7,
    message8,
    message9,
  ]

  const disclosedIndexes = [0, 2, 4, 6]
  const disclosedMessages = disclosedIndexes.map((i) => messages[i])

  const signature = "a47d3c15559d8d54026edc989974057410d65a99e3172420bee8fcd1cf39f96f" +
    "41662f3a5a2cc0d2394e130304eab9fe57aa3941a746616123ee492455f69e43" +
    "af0a64a9bebd1d144f570d879d88fc37"
  const proverBlindness = "643a0c0bc86a50e0d8c00bfe6c8debd85373597e1aef6cc912838bf7dc376e48"

  const proverNym = "3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc"
  const contextId = "bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a"

  const { proof, pseudonym } = pseudo.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    proverNym,
    contextId,
    messages,
    undefined,
    disclosedIndexes,
    undefined,
    proverBlindness,
    cipher,
  )

  const result = pseudo.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    pseudonym,
    contextId,
    10,
    disclosedMessages,
    undefined,
    disclosedIndexes,
    undefined,
    cipher,
  )

  assert(result)
})

Deno.test("Sha-256 signature for pseudonym, hidden pid value, all messages", () => {
  const cipher = CONSTANT.Cipher.XMD_SHA_256
  const header = "11223344556677889900aabbccddeeff"
  const proverNym = "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418"

  const secretKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const message0 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const message1 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const message2 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const message3 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const message4 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const message5 = "515ae153e22aae04ad16f759e07237b4"
  const message6 = "d183ddc6e2665aa4e2f088af"
  const message7 = "ac55fb33a75909ed"
  const message8 = "96012096"
  const message9 = ""

  const messages = [
    message0,
    message1,
    message2,
    message3,
    message4,
    message5,
    message6,
    message7,
    message8,
    message9,
  ]
  const committedMessages = new Array<string>()

  const commitmentWithProof = "b989fc492e2047f602504eb3e236c0acb04224c77ad0d4cbd31c887b9eb05a1f" +
    "27d7acfb266fe0ae062914bfa060984c5c2ac3247080eb71fefc7e9622ffae37" +
    "2425a699a298ba991a0bc5c6a3d9211347d0ce98d5c0550667269df1fb81f8fa" +
    "30c07d4917c7c0786411ee5c05b00b9d501d3f8e244b860b7b11140cddc9787a" +
    "3ab54ec7fd0a8950dae339f396f2641b"
  const proverBlindness = "3ba0a2583bc7229fa9f2ae3a6697091032947c3a48f302b7fd2b08ca9d193041"

  const { signature, entropy } = pseudo.sign(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
  const result = pseudo.verify(
    publicKey,
    signature,
    header,
    messages,
    committedMessages,
    proverNym,
    entropy,
    proverBlindness,
    cipher,
  )
  assert(result)
})

Deno.test("Sha-256 proof for pseudonym, multiple messages revealed", () => {
  const cipher = CONSTANT.Cipher.XMD_SHA_256

  const header = "11223344556677889900aabbccddeeff"
  const presentationHeader = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501"

  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const message0 = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const message1 = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"
  const message2 = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73"
  const message3 = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c"
  const message4 = "496694774c5604ab1b2544eababcf0f53278ff50"
  const message5 = "515ae153e22aae04ad16f759e07237b4"
  const message6 = "d183ddc6e2665aa4e2f088af"
  const message7 = "ac55fb33a75909ed"
  const message8 = "96012096"
  const message9 = ""

  const messages = [
    message0,
    message1,
    message2,
    message3,
    message4,
    message5,
    message6,
    message7,
    message8,
    message9,
  ]

  const disclosedIndexes = [0, 2, 4, 6]
  const disclosedMessages = disclosedIndexes.map((i) => messages[i])

  const signature = "a8c362043de23de5331483e510aafca643d7d1ace1b50003f4cc0eb250868531" +
    "d401e0d3af8a35dc596ef209f41b4f6f28f5c63f8a096e2a3072633fa624872c" +
    "3f6f41fb5121b354ad7d0c0ea07e0f2f"
  const proverBlindness = "3ba0a2583bc7229fa9f2ae3a6697091032947c3a48f302b7fd2b08ca9d193041"

  const proverNym = "3183d923c36e56a823ea4ae0de4287ca87ff06e5785a57268b39a5fa0269bbdc"
  const contextId = "bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a"

  const { proof, pseudonym } = pseudo.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    proverNym,
    contextId,
    messages,
    undefined,
    disclosedIndexes,
    undefined,
    proverBlindness,
    cipher,
  )

  const result = pseudo.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    pseudonym,
    contextId,
    10,
    disclosedMessages,
    undefined,
    disclosedIndexes,
    undefined,
    cipher,
  )

  assert(result)
})
