# bbs-signature

BBS Signature implementation written in Rust and compiled to WASM for JavaScript and TypeScript usage. The interface
specifications are compatible with the
[IETF draft version 7](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-07).

## Usage
To generate a new BLS12-381 keypair for BBS Signature:

```js
const {secretKey, publicKey} = generateKeypair()
```