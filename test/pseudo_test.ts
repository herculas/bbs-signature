import { assert } from "@std/assert"

import * as pseudo from "../lib/pseudonym.ts"
import * as CONSTANT from "../lib/constants.ts"

Deno.test("Shake-256 signature, no prover committed messages, no signer messages", () => {
  const cipher = CONSTANT.Cipher.XOF_SHAKE_256

  const header = "11223344556677889900aabbccddeeff"
  const proverNym = "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418"
  const proverBlind = "643a0c0bc86a50e0d8c00bfe6c8debd85373597e1aef6cc912838bf7dc376e48"
  const signerNym = "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5"

  const secretKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const messages: Array<string> = []
  const committedMessages: Array<string> = []

  const commitmentWithProof = "990c1837a8af86843213e5b12fbfc962efcaf8fd0e5812a6237b91b00a47b5a3" +
    "4714a60b4c365f72b47a4d9b656dde4753a18a8286aca2bf58e8bb9a3d77a3e0" +
    "052aefc427e5e47b666255e53cfcaa7d34d36adc13da01798b8eb041652a57c3" +
    "b595ace54ed5eee43370c1697eb5ce996020d88ca5d811c011cde10c6c07dc2f" +
    "4acbc89bd5652414d5b8823a250ed40b"

  const signature = pseudo.sign(secretKey, publicKey, signerNym, commitmentWithProof, header, messages, cipher)
  const result = pseudo.verify(
    publicKey,
    signature,
    header,
    messages,
    committedMessages,
    proverNym,
    signerNym,
    proverBlind,
    cipher,
  )
  assert(result)
})

Deno.test("Shake-256 signature, multiple prover committed messages, no signer messages", () => {
  const cipher = CONSTANT.Cipher.XOF_SHAKE_256

  const header = "11223344556677889900aabbccddeeff"
  const proverNym = "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418"
  const proverBlind = "1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3"
  const signerNym = "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5"

  const secretKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const messages: Array<string> = []
  const committedMessages: Array<string> = [
    "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3",
    "a75d8b634891af92282cc81a675972d1929d3149863c1fc0",
    "835889a40744813a892eff9deb1edaeb",
    "e1ca9729410dc6ba",
    "",
  ]

  const commitmentWithProof = "a9577c3e2f15081c03d2e86789c1d9208bc04409b1ca33c25d06017c8fef5d13" +
    "9aee028ac96b9c09636a45846e9a5ee51f83bfd55f12193061e3f707d11d9993" +
    "d6e08293de7f3dd0a298c21f369208b43b7b401706a9a0a5dcfa12d28d5a59b0" +
    "9da337b435cf4aa2a869842c8e1409004865ce6ff78d345e5c8142c9c440b677" +
    "824ce06a8f70c50bbbb01838a91eb0041fd853c2005109d3aec272dd03346f37" +
    "fc90828490fbedc4fc88e7307662b785653aba1a28a45bca913b7dd778e8bd14" +
    "1652e6f0507c3f836c8852b8ddbf2c62659dbd7b83f096e7b351f2f0dc6046bc" +
    "e3c8d0c5bb892a7a3d76d6bac899b3d356b099f88287ac25e6879d5808f83292" +
    "7c8e28acae41ab3699b5c0f9da4f58bf67d7e87c5ddb6dadd80fe281e158cc7a" +
    "24bc398f84022dc0dc3a123971f7546c"

  const signature = pseudo.sign(secretKey, publicKey, signerNym, commitmentWithProof, header, messages, cipher)
  const result = pseudo.verify(
    publicKey,
    signature,
    header,
    messages,
    committedMessages,
    proverNym,
    signerNym,
    proverBlind,
    cipher,
  )
  assert(result)
})

Deno.test("Shake-256 signature, no prover committed messages, multiple signer messages", () => {
  const cipher = CONSTANT.Cipher.XOF_SHAKE_256

  const header = "11223344556677889900aabbccddeeff"
  const proverNym = "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418"
  const proverBlind = "643a0c0bc86a50e0d8c00bfe6c8debd85373597e1aef6cc912838bf7dc376e48"
  const signerNym = "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5"

  const secretKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const messages: Array<string> = [
    "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
    "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
    "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
    "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
    "496694774c5604ab1b2544eababcf0f53278ff50",
    "515ae153e22aae04ad16f759e07237b4",
    "d183ddc6e2665aa4e2f088af",
    "ac55fb33a75909ed",
    "96012096",
    "",
  ]
  const committedMessages: Array<string> = []

  const commitmentWithProof = "990c1837a8af86843213e5b12fbfc962efcaf8fd0e5812a6237b91b00a47b5a3" +
    "4714a60b4c365f72b47a4d9b656dde4753a18a8286aca2bf58e8bb9a3d77a3e0" +
    "052aefc427e5e47b666255e53cfcaa7d34d36adc13da01798b8eb041652a57c3" +
    "b595ace54ed5eee43370c1697eb5ce996020d88ca5d811c011cde10c6c07dc2f" +
    "4acbc89bd5652414d5b8823a250ed40b"

  const signature = pseudo.sign(secretKey, publicKey, signerNym, commitmentWithProof, header, messages, cipher)
  const result = pseudo.verify(
    publicKey,
    signature,
    header,
    messages,
    committedMessages,
    proverNym,
    signerNym,
    proverBlind,
    cipher,
  )
  assert(result)
})

Deno.test("Shake-256 signature, multiple prover committed messages, multiple signer messages", () => {
  const cipher = CONSTANT.Cipher.XOF_SHAKE_256

  const header = "11223344556677889900aabbccddeeff"
  const proverNym = "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418"
  const proverBlind = "1ade8b27cccac993dfe3d57be0cd1a200a5cae52d9ea525f106c94f06fea89c3"
  const signerNym = "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5"

  const secretKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const messages: Array<string> = [
    "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
    "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
    "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
    "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
    "496694774c5604ab1b2544eababcf0f53278ff50",
    "515ae153e22aae04ad16f759e07237b4",
    "d183ddc6e2665aa4e2f088af",
    "ac55fb33a75909ed",
    "96012096",
    "",
  ]
  const committedMessages: Array<string> = [
    "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3",
    "a75d8b634891af92282cc81a675972d1929d3149863c1fc0",
    "835889a40744813a892eff9deb1edaeb",
    "e1ca9729410dc6ba",
    "",
  ]

  const commitmentWithProof = "a9577c3e2f15081c03d2e86789c1d9208bc04409b1ca33c25d06017c8fef5d13" +
    "9aee028ac96b9c09636a45846e9a5ee51f83bfd55f12193061e3f707d11d9993" +
    "d6e08293de7f3dd0a298c21f369208b43b7b401706a9a0a5dcfa12d28d5a59b0" +
    "9da337b435cf4aa2a869842c8e1409004865ce6ff78d345e5c8142c9c440b677" +
    "824ce06a8f70c50bbbb01838a91eb0041fd853c2005109d3aec272dd03346f37" +
    "fc90828490fbedc4fc88e7307662b785653aba1a28a45bca913b7dd778e8bd14" +
    "1652e6f0507c3f836c8852b8ddbf2c62659dbd7b83f096e7b351f2f0dc6046bc" +
    "e3c8d0c5bb892a7a3d76d6bac899b3d356b099f88287ac25e6879d5808f83292" +
    "7c8e28acae41ab3699b5c0f9da4f58bf67d7e87c5ddb6dadd80fe281e158cc7a" +
    "24bc398f84022dc0dc3a123971f7546c"

  const signature = pseudo.sign(secretKey, publicKey, signerNym, commitmentWithProof, header, messages, cipher)
  const result = pseudo.verify(
    publicKey,
    signature,
    header,
    messages,
    committedMessages,
    proverNym,
    signerNym,
    proverBlind,
    cipher,
  )
  assert(result)
})

Deno.test("Sha-256 signature, no prover committed messages, no signer messages", () => {
  const cipher = CONSTANT.Cipher.XMD_SHA_256

  const header = "11223344556677889900aabbccddeeff"
  const proverNym = "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418"
  const proverBlind = "3ba0a2583bc7229fa9f2ae3a6697091032947c3a48f302b7fd2b08ca9d193041"
  const signerNym = "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5"

  const secretKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const messages: Array<string> = []
  const committedMessages: Array<string> = []

  const commitmentWithProof = "b989fc492e2047f602504eb3e236c0acb04224c77ad0d4cbd31c887b9eb05a1f" +
    "27d7acfb266fe0ae062914bfa060984c5c2ac3247080eb71fefc7e9622ffae37" +
    "2425a699a298ba991a0bc5c6a3d9211347d0ce98d5c0550667269df1fb81f8fa" +
    "30c07d4917c7c0786411ee5c05b00b9d501d3f8e244b860b7b11140cddc9787a" +
    "3ab54ec7fd0a8950dae339f396f2641b"

  const signature = pseudo.sign(secretKey, publicKey, signerNym, commitmentWithProof, header, messages, cipher)
  const result = pseudo.verify(
    publicKey,
    signature,
    header,
    messages,
    committedMessages,
    proverNym,
    signerNym,
    proverBlind,
    cipher,
  )
  assert(result)
})

Deno.test("Sha-256 signature, multiple prover committed messages, no signer messages", () => {
  const cipher = CONSTANT.Cipher.XMD_SHA_256

  const header = "11223344556677889900aabbccddeeff"
  const proverNym = "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418"
  const proverBlind = "15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8"
  const signerNym = "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5"

  const secretKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const messages: Array<string> = []
  const committedMessages: Array<string> = [
    "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3",
    "a75d8b634891af92282cc81a675972d1929d3149863c1fc0",
    "835889a40744813a892eff9deb1edaeb",
    "e1ca9729410dc6ba",
    "",
  ]

  const commitmentWithProof = "99efccc0ccd91efabb8821ee33edacb823b1dd999682aaa54f38a9c4585e7e7a" +
    "a746357b2842d38c008f6d732dd501c70eed41caf3eafdd4bb6151ce2c028940" +
    "1c7d13381e7db90137d7aa2a64224aa2499a4548b2654481a2f0dd16d799116f" +
    "e41db7b7a5c3ae8b1c64bef6a89a46f5040a5178d2e1126f7f35189f0f6cea38" +
    "03e679ce92eff73856b164425ac4ff8405a934f65ada8ccbe21558ab66db1136" +
    "62ea17ce0c9aa0280db20dcf79301c61269ddfdbdcc22025b85f7089c4ebebc2" +
    "24a938b745daae833ac4698d9d32bfa8382b4bbb2679ae232d2f6e8e19239e6e" +
    "a919665ea736b45a61bbd0e4f4d7431f3038c3db25833b9a0cc1a7709419ac24" +
    "1fb6f02ee13e51101743f1983d3fa69b5d344b984c48a265ee6a7b0df8450004" +
    "ceec7c1997b859be16af624e3da2cf44"

  const signature = pseudo.sign(secretKey, publicKey, signerNym, commitmentWithProof, header, messages, cipher)
  const result = pseudo.verify(
    publicKey,
    signature,
    header,
    messages,
    committedMessages,
    proverNym,
    signerNym,
    proverBlind,
    cipher,
  )
  assert(result)
})

Deno.test("Sha-256 signature, no prover committed messages, multiple signer messages", () => {
  const cipher = CONSTANT.Cipher.XMD_SHA_256

  const header = "11223344556677889900aabbccddeeff"
  const proverNym = "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418"
  const proverBlind = "3ba0a2583bc7229fa9f2ae3a6697091032947c3a48f302b7fd2b08ca9d193041"
  const signerNym = "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5"

  const secretKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const messages: Array<string> = [
    "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
    "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
    "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
    "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
    "496694774c5604ab1b2544eababcf0f53278ff50",
    "515ae153e22aae04ad16f759e07237b4",
    "d183ddc6e2665aa4e2f088af",
    "ac55fb33a75909ed",
    "96012096",
    "",
  ]
  const committedMessages: Array<string> = []

  const commitmentWithProof = "b989fc492e2047f602504eb3e236c0acb04224c77ad0d4cbd31c887b9eb05a1f" +
    "27d7acfb266fe0ae062914bfa060984c5c2ac3247080eb71fefc7e9622ffae37" +
    "2425a699a298ba991a0bc5c6a3d9211347d0ce98d5c0550667269df1fb81f8fa" +
    "30c07d4917c7c0786411ee5c05b00b9d501d3f8e244b860b7b11140cddc9787a" +
    "3ab54ec7fd0a8950dae339f396f2641b"

  const signature = pseudo.sign(secretKey, publicKey, signerNym, commitmentWithProof, header, messages, cipher)
  const result = pseudo.verify(
    publicKey,
    signature,
    header,
    messages,
    committedMessages,
    proverNym,
    signerNym,
    proverBlind,
    cipher,
  )
  assert(result)
})

Deno.test("Sha-256 signature, multiple prover committed messages, multiple signer messages", () => {
  const cipher = CONSTANT.Cipher.XMD_SHA_256

  const header = "11223344556677889900aabbccddeeff"
  const proverNym = "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418"
  const proverBlind = "15494ae70742a6a4f420106c79ee405c138557385f3f6f7256449d147ebf22b8"
  const signerNym = "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5"

  const secretKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const messages: Array<string> = [
    "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
    "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
    "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
    "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
    "496694774c5604ab1b2544eababcf0f53278ff50",
    "515ae153e22aae04ad16f759e07237b4",
    "d183ddc6e2665aa4e2f088af",
    "ac55fb33a75909ed",
    "96012096",
    "",
  ]
  const committedMessages: Array<string> = [
    "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3",
    "a75d8b634891af92282cc81a675972d1929d3149863c1fc0",
    "835889a40744813a892eff9deb1edaeb",
    "e1ca9729410dc6ba",
    "",
  ]

  const commitmentWithProof = "99efccc0ccd91efabb8821ee33edacb823b1dd999682aaa54f38a9c4585e7e7a" +
    "a746357b2842d38c008f6d732dd501c70eed41caf3eafdd4bb6151ce2c028940" +
    "1c7d13381e7db90137d7aa2a64224aa2499a4548b2654481a2f0dd16d799116f" +
    "e41db7b7a5c3ae8b1c64bef6a89a46f5040a5178d2e1126f7f35189f0f6cea38" +
    "03e679ce92eff73856b164425ac4ff8405a934f65ada8ccbe21558ab66db1136" +
    "62ea17ce0c9aa0280db20dcf79301c61269ddfdbdcc22025b85f7089c4ebebc2" +
    "24a938b745daae833ac4698d9d32bfa8382b4bbb2679ae232d2f6e8e19239e6e" +
    "a919665ea736b45a61bbd0e4f4d7431f3038c3db25833b9a0cc1a7709419ac24" +
    "1fb6f02ee13e51101743f1983d3fa69b5d344b984c48a265ee6a7b0df8450004" +
    "ceec7c1997b859be16af624e3da2cf44"

  const signature = pseudo.sign(secretKey, publicKey, signerNym, commitmentWithProof, header, messages, cipher)
  const result = pseudo.verify(
    publicKey,
    signature,
    header,
    messages,
    committedMessages,
    proverNym,
    signerNym,
    proverBlind,
    cipher,
  )
  assert(result)
})
