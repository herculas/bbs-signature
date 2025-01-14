use crate::suite::constants::LENGTH_G1_POINT;
use bls12_381::{G1Affine, G2Prepared, Gt};

pub struct Cipher {
    /// The unique identifier for the cipher suite, which will be represented as an ASCII string.
    ///
    /// The REQUIRED format for the string is `BBS_ || <h2c_suite_id> || <add_info>`, where:
    /// - `BBS_` is a constant prefix.
    /// - `<h2c_suite_id>` is the identifier of the hash-to-curve suite, and
    /// - `<add_info>` is an optional string that indicating any additional information used to uniquely identify the
    ///         suite. When specified, this value MUST only contain ASCII characters with codes between 0x21 and 0x7E,
    ///         inclusive, and MUST end with an underscore.
    pub id: &'static [u8],

    /// A fixed point in the G1 group, different from the identity element.
    ///
    /// This leaves the identity element free for use in other protocols, like key commitment and proof of possession.
    pub singularity: [u8; LENGTH_G1_POINT],

    /// A cryptographic hash function that takes an arbitrary octet string as input, and returns a point in G1.
    ///
    /// - `msg`: An octet string representing the message to be hashed.
    /// - `dst`: A domain separation tag.
    ///
    /// Return a point in G1.
    pub hash_to_curve: fn(message: &[u8], dst: &[u8]) -> G1Affine,

    /// The operation used to expand a message to a scalar.
    ///
    /// - `msg`: An octet string representing the message to be expanded.
    /// - `dst`: A domain separation tag.
    /// - `len`: The number of bytes to expand the message to.
    ///
    /// Return an octet string representing the expanded message.
    pub expand_message: fn(message: &[u8], dst: &[u8], expand_length: Option<usize>) -> Vec<u8>,

    /// Compare two pairing results for equality.
    ///
    /// - `terms`: A list of pairs of points in G1 and G2.
    /// - `result`: The target pairing result, a point in Gt.
    ///
    /// Return `true` if the product of the pairing results are equal to the target result.
    pub pairing_compare: fn(terms: &[(&G1Affine, &G2Prepared)], result: &Gt) -> bool,
}
