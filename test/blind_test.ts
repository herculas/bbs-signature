import { assert } from "@std/assert"

import * as blind from "../lib/blind.ts"
import * as CONSTANT from "../lib/constants.ts"

Deno.test("Shake-256 signature for blind no prover committed messages, no signer messages", () => {
  const cipher = CONSTANT.Cipher.XOF_SHAKE_256
  const header = "11223344556677889900aabbccddeeff"

  const secretKey = "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

  const messages = new Array<string>()
  const committedMessages = new Array<string>()

  const { commitmentWithProof, proverBlindness } = blind.commit(committedMessages, cipher)

  const signature = blind.sign(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
  const result = blind.verify(publicKey, signature, header, messages, committedMessages, proverBlindness, cipher)

  assert(result)
})

Deno.test("Shake-256 signature for blind multiple prover committed messages, no signer messages", () => {
  const cipher = CONSTANT.Cipher.XOF_SHAKE_256
  const header = "11223344556677889900aabbccddeeff"

  const secretKey = "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

  const messages = new Array<string>()
  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const { commitmentWithProof, proverBlindness } = blind.commit(committedMessages, cipher)

  const signature = blind.sign(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
  const result = blind.verify(publicKey, signature, header, messages, committedMessages, proverBlindness, cipher)

  assert(result)
})

Deno.test("Shake-256 signature for blind no prover committed messages, multiple signer messages", () => {
  const cipher = CONSTANT.Cipher.XOF_SHAKE_256
  const header = "11223344556677889900aabbccddeeff"

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

  const { commitmentWithProof, proverBlindness } = blind.commit(committedMessages, cipher)

  const signature = blind.sign(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
  const result = blind.verify(publicKey, signature, header, messages, committedMessages, proverBlindness, cipher)

  assert(result)
})

Deno.test("Shake-256 signature for blind multiple prover committed messages, multiple signer messages", () => {
  const cipher = CONSTANT.Cipher.XOF_SHAKE_256
  const header = "11223344556677889900aabbccddeeff"

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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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
  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const { commitmentWithProof, proverBlindness } = blind.commit(committedMessages, cipher)

  const signature = blind.sign(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
  const result = blind.verify(publicKey, signature, header, messages, committedMessages, proverBlindness, cipher)

  assert(result)
})

Deno.test("Shake-256 signature for blind undefined prover committed messages, multiple signer messages", () => {
  const cipher = CONSTANT.Cipher.XOF_SHAKE_256
  const header = "11223344556677889900aabbccddeeff"

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

  const signature = blind.sign(secretKey, publicKey, undefined, header, messages, cipher)
  const result = blind.verify(publicKey, signature, header, messages, undefined, undefined, cipher)

  assert(result)
})

Deno.test("Shake-256 proof for all prover committed messages and signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  const disclosedCommitmentIndexes = [0, 1, 2, 3, 4]

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61" +
    "fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1" +
    "5ab02449b8d375f869a8df15db78eb02"
  const proverBlindness = "41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Shake-256 proof for half prover committed messages and all signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  const disclosedCommitmentIndexes = [0, 2, 4]

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61" +
    "fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1" +
    "5ab02449b8d375f869a8df15db78eb02"
  const proverBlindness = "41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Shake-256 proof for all prover committed messages and half signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = [0, 2, 4, 6, 8]
  const disclosedCommitmentIndexes = [0, 1, 2, 3, 4]

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61" +
    "fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1" +
    "5ab02449b8d375f869a8df15db78eb02"
  const proverBlindness = "41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Shake-256 proof for half prover committed messages and half signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = [0, 2, 4, 6, 8]
  const disclosedCommitmentIndexes = [0, 2, 4]

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61" +
    "fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1" +
    "5ab02449b8d375f869a8df15db78eb02"
  const proverBlindness = "41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Shake-256 proof for no prover committed messages and half signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = [0, 2, 4, 6, 8]
  const disclosedCommitmentIndexes = new Array<number>()

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61" +
    "fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1" +
    "5ab02449b8d375f869a8df15db78eb02"
  const proverBlindness = "41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Shake-256 proof for half prover committed messages and no signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = new Array<number>()
  const disclosedCommitmentIndexes = [0, 2, 4]

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61" +
    "fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1" +
    "5ab02449b8d375f869a8df15db78eb02"
  const proverBlindness = "41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Shake-256 proof for no prover committed messages and no signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = new Array<number>()
  const disclosedCommitmentIndexes = new Array<number>()

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "80b1195ea9e11a639e11e2dc653ccca0461055edb4f48a6e80b676636e42dd61" +
    "fae3e52c04e192d5053d60e73f3dec5048d423579dcb96cde6969f8048ce53f1" +
    "5ab02449b8d375f869a8df15db78eb02"
  const proverBlindness = "41fb2f74c30256398c927a262602b5ac3ebc6f84d9169476f8fcb1525c93b649"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Shake-256 proof for undefined prover committed messages and half signer messages revealed", () => {
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

  const disclosedIndexes = [0, 2, 4, 6, 8]
  const disclosedMessages = disclosedIndexes.map((i) => messages[i])

  const signature = "b80f73e22cf6c050159018539af4fd2c8ed75a7dfa247feadbdecd983e16ddb3" +
    "3ac5c61bfd7f17b4063a7957456ddc0b71d46e6a05b1a464df601aabf480edf1" +
    "7ff1d6052089c294577fcfb7b851baad"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    undefined,
    disclosedIndexes,
    undefined,
    undefined,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    undefined,
    disclosedIndexes,
    undefined,
    cipher,
  )

  assert(result)
})

Deno.test("Sha-256 signature for blind no prover committed messages, no signer messages", () => {
  const cipher = CONSTANT.Cipher.XMD_SHA_256
  const header = "11223344556677889900aabbccddeeff"

  const secretKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const messages = new Array<string>()
  const committedMessages = new Array<string>()

  const { commitmentWithProof, proverBlindness } = blind.commit(committedMessages, cipher)

  const signature = blind.sign(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
  const result = blind.verify(publicKey, signature, header, messages, committedMessages, proverBlindness, cipher)

  assert(result)
})

Deno.test("Sha-256 signature for blind multiple prover committed messages, no signer messages", () => {
  const cipher = CONSTANT.Cipher.XMD_SHA_256
  const header = "11223344556677889900aabbccddeeff"

  const secretKey = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc"
  const publicKey = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f28" +
    "51bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f" +
    "1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c"

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

  const messages = new Array<string>()
  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const { commitmentWithProof, proverBlindness } = blind.commit(committedMessages, cipher)

  const signature = blind.sign(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
  const result = blind.verify(publicKey, signature, header, messages, committedMessages, proverBlindness, cipher)

  assert(result)
})

Deno.test("Sha-256 signature for blind no prover committed messages, multiple signer messages", () => {
  const cipher = CONSTANT.Cipher.XMD_SHA_256
  const header = "11223344556677889900aabbccddeeff"

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

  const { commitmentWithProof, proverBlindness } = blind.commit(committedMessages, cipher)

  const signature = blind.sign(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
  const result = blind.verify(publicKey, signature, header, messages, committedMessages, proverBlindness, cipher)

  assert(result)
})

Deno.test("Sha-256 signature for blind multiple prover committed messages, multiple signer messages", () => {
  const cipher = CONSTANT.Cipher.XMD_SHA_256
  const header = "11223344556677889900aabbccddeeff"

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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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
  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const { commitmentWithProof, proverBlindness } = blind.commit(committedMessages, cipher)

  const signature = blind.sign(secretKey, publicKey, commitmentWithProof, header, messages, cipher)
  const result = blind.verify(publicKey, signature, header, messages, committedMessages, proverBlindness, cipher)

  assert(result)
})

Deno.test("Sha-256 signature for blind undefined prover committed messages, multiple signer messages", () => {
  const cipher = CONSTANT.Cipher.XMD_SHA_256
  const header = "11223344556677889900aabbccddeeff"

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

  const signature = blind.sign(secretKey, publicKey, undefined, header, messages, cipher)
  const result = blind.verify(publicKey, signature, header, messages, undefined, undefined, cipher)

  assert(result)
})

Deno.test("Sha-256 proof for all prover committed messages and signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  const disclosedCommitmentIndexes = [0, 1, 2, 3, 4]

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c" +
    "3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc" +
    "aa8feb7f3a236e92b2da38462358c48a"
  const proverBlindness = "4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Sha-256 proof for half prover committed messages and all signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  const disclosedCommitmentIndexes = [0, 2, 4]

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c" +
    "3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc" +
    "aa8feb7f3a236e92b2da38462358c48a"
  const proverBlindness = "4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Sha-256 proof for all prover committed messages and half signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = [0, 2, 4, 6, 8]
  const disclosedCommitmentIndexes = [0, 1, 2, 3, 4]

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c" +
    "3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc" +
    "aa8feb7f3a236e92b2da38462358c48a"
  const proverBlindness = "4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Sha-256 proof for half prover committed messages and half signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = [0, 2, 4, 6, 8]
  const disclosedCommitmentIndexes = [0, 2, 4]

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c" +
    "3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc" +
    "aa8feb7f3a236e92b2da38462358c48a"
  const proverBlindness = "4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Sha-256 proof for no prover committed messages and half signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = [0, 2, 4, 6, 8]
  const disclosedCommitmentIndexes = new Array<number>()

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c" +
    "3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc" +
    "aa8feb7f3a236e92b2da38462358c48a"
  const proverBlindness = "4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Sha-256 proof for half prover committed messages and no signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = new Array<number>()
  const disclosedCommitmentIndexes = [0, 2, 4]

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c" +
    "3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc" +
    "aa8feb7f3a236e92b2da38462358c48a"
  const proverBlindness = "4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Sha-256 proof for no prover committed messages and no signer messages revealed", () => {
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

  const committedMessage0 = "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"
  const committedMessage1 = "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"
  const committedMessage2 = "835889a40744813a892eff9deb1edaeb"
  const committedMessage3 = "e1ca9729410dc6ba"
  const committedMessage4 = ""

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

  const committedMessages = [
    committedMessage0,
    committedMessage1,
    committedMessage2,
    committedMessage3,
    committedMessage4,
  ]

  const disclosedIndexes = new Array<number>()
  const disclosedCommitmentIndexes = new Array<number>()

  const disclosedMessages = disclosedIndexes.map((i) => messages[i])
  const disclosedCommittedMessages = disclosedCommitmentIndexes.map((i) => committedMessages[i])

  const signature = "862eb2fedd0a2b76fb978035cb33952004bdd6136e107bb343cb2c5ea566eb0c" +
    "3b0ba31b1d022ebf03d0abf050ab293c0afd9c96003331aa13f18a7a47e2e1cc" +
    "aa8feb7f3a236e92b2da38462358c48a"
  const proverBlindness = "4fba5396baa36b2fde81d46a9b9ee89c425dbc5e1ffd65c20249afb4abd37589"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    committedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    proverBlindness,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    disclosedCommittedMessages,
    disclosedIndexes,
    disclosedCommitmentIndexes,
    cipher,
  )

  assert(result)
})

Deno.test("Sha-256 proof for undefined prover committed messages and half signer messages revealed", () => {
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

  const disclosedIndexes = [0, 2, 4, 6, 8]
  const disclosedMessages = disclosedIndexes.map((i) => messages[i])

  const signature = "8aa8fdfb190987d1fe1c8e34e69eae25594701958064e4483d74580a4a0f51f0" +
    "58a87735d727383b864904aa7b5e4a9b3821a18319df0ccb2e351a9bf75bf1f3" +
    "4d8858dde57119bfafd8ff56e0c54fa4"

  const proof = blind.prove(
    publicKey,
    signature,
    header,
    presentationHeader,
    messages,
    undefined,
    disclosedIndexes,
    undefined,
    undefined,
    cipher,
  )

  const result = blind.validate(
    publicKey,
    proof,
    header,
    presentationHeader,
    10,
    disclosedMessages,
    undefined,
    disclosedIndexes,
    undefined,
    cipher,
  )

  assert(result)
})
