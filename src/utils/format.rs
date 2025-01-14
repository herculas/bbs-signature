/// Transfer a vector of bytes to a hex string.
///
/// - `bytes`: a vector of bytes.
///
/// Return a hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Transfer a hex string to a vector of bytes.
///
/// - `hex`: a hex string.
///
/// Return a vector of bytes.
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("[Serialization] The input string should be in hex format!")
}

/// Convert a non-negative integer into an octet string of a specified length.
///
/// - `value`: a non-negative integer to be converted.
/// - `length`: the intended length of the resulting octet string.
///
/// Return an octet string in big-endian format.
pub fn i2osp(value: u64, length: usize) -> Vec<u8> {
    let mut result = vec![0; length];
    let mut v = value;
    for i in (0..length).rev() {
        result[i] = (v & 0xff) as u8;
        v >>= 8;
    }
    result
}

/// Convert an octet string into a non-negative integer.
///
/// - `bytes`: an octet string to be converted, in big-endian format.
///
/// Return a non-negative integer.
pub fn os2ip(bytes: &[u8]) -> u64 {
    let mut result = 0;
    for byte in bytes {
        result = (result << 8) + *byte as u64;
    }
    result
}

/// Concatenate multiple arrays of bytes into a single array.
///
/// - `bytes`: an array of arrays of bytes.
///
/// Return a single array of bytes.
pub fn concat_bytes(bytes: &[&[u8]]) -> Vec<u8> {
    bytes.iter().flat_map(|b| b.iter()).copied().collect()
}
