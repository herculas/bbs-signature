# bbs-signature

[![Check](https://github.com/herculas/bbs-signature/actions/workflows/check.yml/badge.svg?branch=rust)](https://github.com/herculas/bbs-signature/actions/workflows/check.yml)

BBS Signature implementation written in Rust and compiled to WASM for JavaScript and TypeScript usage. The interface
specifications are compatible with the
[IETF draft version 7](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07).

## Getting started

To refer to this package within your Deno project, run:

```shell
deno add jsr:@crumble-jon/bbs-signature
```

## Usage

### Keypair generation

Generate a BLS12-381 keypair deterministically from a secret key material, an info string, and a domain separation tag.

```js
const { secretKey, publicKey } = generateKeypair(
  "<key_material>",
  "<key_info>",
  "<key_dst>",
  "BLS12_381_G1_XOF_SHAKE_256" | "BLS12_381_G1_XMD_SHA_256",
)
```

### Signing

Generate a BBS Signature from a secret key, over a header, and a set of messages.

```js
const signature = sign(
  "<secret_key>",
  "<public_key>",
  "<header>",
  "<messages>",
  "BLS12_381_G1_XOF_SHAKE_256" | "BLS12_381_G1_XMD_SHA_256",
)
```

### Verifying

Validate a BBS Signature, given a public key, a header, and a set of messages.

```js
const verification = verify(
  "<public_key>",
  "<signature>",
  "<header>",
  "<messages>",
  "BLS12_381_G1_XOF_SHAKE_256" | "BLS12_381_G1_XMD_SHA_256",
)
```

### Proving

Generate a BBS proof, which is a zero-knowledge proof-of-knowledge of a BBS Signature, while optionally disclosing any
subset of the signed messages.

Other than the signer's public key, the BBS Signature and the signed header and messages, the operation also accepts a
presentation header, which will be bound to the resulting proof. To indicate which of the messages are to be disclosed,
the operation accepts a list of integers in ascending order, representing the indexes of those messages.

```js
const proof = prove(
  "<public_key>",
  "<signature>",
  "<header>",
  "<presentation_header>",
  "<messages>",
  "<disclosed_indexes>",
  "BLS12_381_G1_XOF_SHAKE_256" | "BLS12_381_G1_XMD_SHA_256",
)
```

### Proof validating

Validate a BBS proof, given the signer's public key, a header, a presentation header, the disclosed messages, and the
indexes of those messages in the original vector of signed messages.

Validating the proof guarantees authenticity and integrity of the header and disclosed messages, as well as knowledge of
a valid BBS Signature.

```js
const validation = validate(
  "<public_key>",
  "<proof>",
  "<presentation_header>",
  "<disclosed_messages>",
  "<disclosed_indexes>",
  "BLS12_381_G1_XOF_SHAKE_256" | "BLS12_381_G1_XMD_SHA_256",
)
```
