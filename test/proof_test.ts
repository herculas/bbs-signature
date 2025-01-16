import { assert } from "@std/assert"
import { prove, validate } from "../lib/mod.ts"

Deno.test("shake-256 proof for single message", () => {
  const header = "11223344556677889900aabbccddeeff"
  const presentationHeader = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501"

  const msg = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"
  const publicKey = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb1" +
    "8fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179" +
    "eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

  const signature = "b9a622a4b404e6ca4c85c15739d2124a1deb16df750be202e2430e169bc27fb7" +
    "1c44d98e6d40792033e1c452145ada95030832c5dc778334f2f1b528eced21b0" +
    "b97a12025a283d78b7136bb9825d04ef"

  const proof = prove(publicKey, signature, header, presentationHeader, [msg], [0], "BLS12_381_G1_XOF_SHAKE_256")
  const verification = validate(publicKey, proof, header, presentationHeader, [msg], [0], "BLS12_381_G1_XOF_SHAKE_256")

  assert(verification)
})
