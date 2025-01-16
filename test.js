import {generate_secret_key, derive_public_key, sign, verify, prove, validate} from "./pkg/bbs_signature.js";

const material = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579"
const info = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e"
const dst = "4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f"

const secret_key_shake = generate_secret_key(material, info, dst, "BLS12_381_G1_XOF_SHAKE_256");
const public_key_shake = derive_public_key(secret_key_shake);

// console.log(secret_key_shake);
// console.log(public_key_shake);

const secret_key = "2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079"
const public_key = "92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5"

const header = "11223344556677889900aabbccddeeff"
const msg = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"

let signature = sign(secret_key, public_key, header, [msg], "BLS12_381_G1_XOF_SHAKE_256");
let verification = verify(public_key, signature, header, [msg], "BLS12_381_G1_XOF_SHAKE_256");

// console.log(signature);
// console.log(verification);

const presentation_header = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501";


let proof = prove(
    public_key,
    signature,
    header,
    presentation_header,
    [msg],
    [0],
    "BLS12_381_G1_XOF_SHAKE_256");

let result = validate(
    public_key,
    proof,
    header,
    presentation_header,
    [msg],
    [0],
    "BLS12_381_G1_XOF_SHAKE_256");

console.log(proof);
console.log(result);