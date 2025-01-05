// import { Cipher } from "../cipher/interface.ts"
// import { Scalar } from "../cipher/elements.ts"

// /**
//  * Create a BBS proof, which is a zero-knowledge proof, i.e., a proof-of-knowledge of a BBS signature, while optionally
//  * disclosing any subset of the signed messages.
//  *
//  * Other than the signer's public key, the BBS signature and the signed header and messages, the operation also accepts
//  * a presentation header, which will be bound to the resulting proof. To indicate which of the messages are to be
//  * disclosed, the operation accepts a list of integers in ascending order, representing the indexes of those messages.
//  *
//  * @param {Uint8Array} publicKey An octet string representing the public key.
//  * @param {Uint8Array} signature An octet string representing the signature.
//  * @param {Uint8Array} [header] An octet string containing context and application specific information.
//  * @param {Uint8Array} [presentationHeader] An octet string containing the presentation header.
//  * @param {Array<Scalar>} [messages] A vector of scalars representing the messages.
//  * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
//  * @param {Uint8Array} [apiId] An octet string containing the API identifier.
//  * @param {Cipher} cipher A cipher suite.
//  *
//  * @returns {Uint8Array} A proof.
//  *
//  */
// export function prove(
//   publicKey: Uint8Array,
//   signature: Uint8Array,
//   header: Uint8Array = new Uint8Array(),
//   presentationHeader: Uint8Array = new Uint8Array(),
//   messages: Array<Scalar> = new Array<Scalar>(),
//   disclosedIndexes: Array<number> = new Array<number>(),
//   apiId: Uint8Array = new Uint8Array(),
//   cipher: Cipher,
// ): Uint8Array {}

// /**
//  * Validate a BBS proof, given the signer's public key, a header, a presentation header, the disclosed messages, and the
//  * indexes of those messages in the original vector of signed messages.
//  *
//  * Validating the proof guarantees authenticity and integrity of the header and disclosed messages, as well as knowledge
//  * of a valid BBS signature.
//  *
//  * @param {Uint8Array} publicKey An octet string representing the public key.
//  * @param {Uint8Array} proof An octet string representing the proof.
//  * @param {Uint8Array} [header] An octet string containing context and application specific information.
//  * @param {Uint8Array} [presentationHeader] An octet string containing the presentation header.
//  * @param {Array<Uint8Array>} [disclosedMessages] A vector of octet strings representing the disclosed messages.
//  * @param {Array<number>} [disclosedIndexes] A vector of integers representing the indexes of the disclosed messages.
//  * @param {Uint8Array} [apiId] An octet string containing the API identifier.
//  * @param {Cipher} cipher A cipher suite.
//  *
//  * @returns {boolean} `true` if the proof is valid, `false` otherwise.
//  *
//  */
// export function verify(
//   publicKey: Uint8Array,
//   proof: Uint8Array,
//   header: Uint8Array = new Uint8Array(),
//   presentationHeader: Uint8Array = new Uint8Array(),
//   disclosedMessages: Array<Uint8Array> = new Array<Uint8Array>(),
//   disclosedIndexes: Array<number> = new Array<number>(),
//   apiId: Uint8Array = new Uint8Array(),
//   cipher: Cipher,
// ): boolean {}
