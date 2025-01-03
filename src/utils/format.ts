/**
 * Integer to octet string.
 *
 * @param {bigint} value The integer to convert.
 * @param {number} length The length of the resulting octet string.
 *
 * @returns {Uint8Array} The octet string.
 */
export function i2osp(value: bigint, length: number): Uint8Array {
  if (length <= 0 || !Number.isSafeInteger(length)) {
    throw new Error(`bad I2OSP call: length=${length}`)
  }
  if (value < 0 || value >= 1n << (8n * BigInt(length))) {
    throw new Error(`bad I2OSP call: value=${value} length=${length}`)
  }

  const result = new Uint8Array(length)
  for (let i = length - 1; i >= 0; i--) {
    result[i] = Number(value & 0xffn)
    value >>= 8n
  }
  return result
}

/**
 * Octet string to integer.
 *
 * @param {Uint8Array} octets The octet string to convert.
 *
 * @returns {bigint} The integer.
 */
export function os2ip(octets: Uint8Array): bigint {
  const hex = bytesToHex(octets)
  return hex === "" ? BigInt(0) : BigInt(`0x${hex}`)
}

/**
 * Concatenate multiple Uint8Array instances into a single Uint8Array.
 *
 * @param {Array<Uint8Array>} arrays The arrays to concatenate.
 *
 * @returns {Uint8Array} The concatenated array.
 */
export function concatenate(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0)
  const result = new Uint8Array(totalLength)
  arrays.reduce((offset, arr) => {
    result.set(arr, offset)
    return offset + arr.length
  }, 0)
  return result
}

/**
 * Transfer a byte array to a hex string.
 *
 * @param {Uint8Array} bytes A byte array.
 *
 * @returns {string} The hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join("")
}

/**
 * Transfer a hex string to a byte array.
 *
 * @param {string} hex A hex string.
 *
 * @returns {Uint8Array} The byte array.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("hex string must have an even number of characters")
  }
  if (hex.length === 0) {
    return new Uint8Array()
  }
  return new Uint8Array(hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)))
}
