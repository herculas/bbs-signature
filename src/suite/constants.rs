/// Number of bytes representing a scalar value, in the group of integers modulo r.
///
/// It is RECOMMENDED that this value be set to `ceil(log2(r)/8)`.
pub const LENGTH_SCALAR: usize = 32;

/// Number of bytes to represent a point in the group G1.
pub const LENGTH_G1_POINT: usize = 48;

/// Number of bytes to represent a point in the group G2.
pub const LENGTH_G2_POINT: usize = 96;

/// Number of bytes to expand a message.
pub const LENGTH_MESSAGE_EXPAND: usize = 48;

pub const PADDING_API_ID: &[u8] = b"H2G_HM2S_";

pub const PADDING_SIG_GENERATOR_SEED: &[u8] = b"SIG_GENERATOR_SEED_";
pub const PADDING_MSG_GENERATOR_SEED: &[u8] = b"MESSAGE_GENERATOR_SEED";

pub const PADDING_KEYGEN_DST: &[u8] = b"KEYGEN_DST_";
pub const PADDING_SIG_GENERATOR_DST: &[u8] = b"SIG_GENERATOR_DST_";

pub const PADDING_HASH_TO_SCALAR: &[u8] = b"H2S_";
pub const PADDING_MAP_TO_SCALAR: &[u8] = b"MAP_MSG_TO_SCALAR_AS_HASH_";

#[allow(dead_code)]
pub const PADDING_SEED_RANDOM_SCALAR: &[u8] = b"MOCK_RANDOM_SCALARS_DST_";
