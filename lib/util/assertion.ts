import { Cipher } from "../constant/cipher.ts"

/**
 * Assert that the provided value is a existing value.
 *
 * @param {unknown} value The value to be validated.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertExist(value: unknown, message?: string) {
  if (value === undefined || value === null) {
    throw new Error(message || "The provided value does not exist.")
  }
}

/**
 * Assert that the provided value is a valid even-length string.
 *
 * @param {string} [str] The string to be validated.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertEvenLength(str?: string, message?: string) {
  if (!str) return
  if (str.length % 2 !== 0) {
    throw new Error(message || "The provided string MUST have an even length.")
  }
}

/**
 * Assert that the provided value is encoded in hexadecimal format.
 *
 * @param {string} [str] The string to be validated.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertHexEncoding(str?: string, message?: string) {
  if (!str) return
  if (!/^[0-9a-fA-F]*$/.test(str)) {
    throw new Error(message || "The provided string MUST be encoded in hexadecimal format.")
  }
}

/**
 * Assert that the provided value is a valid hex string.
 *
 * @param {string} [str] The string to be validated.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertHexString(str?: string, message?: string) {
  assertEvenLength(str, message)
  assertHexEncoding(str, message)
}

/**
 * Assert that the provided value is a valid string of a length less than or equal to a given length.
 *
 * @param {string} str The string to be validated.
 * @param {number} length The maximum length the string should be.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertLengthMax(str: string, length: number, message?: string) {
  if (str.length > length) {
    throw new Error(message || `The provided string MUST be no longer than ${length}.`)
  }
}

/**
 * Assert that the provided value is a valid string of a length greater than or equal to a given length.
 *
 * @param {string} str The string to be validated.
 * @param {number} length The minimum length the string should be.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertLengthMin(str: string, length: number, message?: string) {
  if (str.length < length) {
    throw new Error(message || `The provided string MUST be at least ${length}.`)
  }
}

/**
 * Assert that the provided value is a valid string of a given length.
 *
 * @param {string} str The string to be validated.
 * @param {number} length The length the string should be.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertLength(str: string, length: number, message?: string) {
  if (str.length !== length) {
    throw new Error(message || `The provided string MUST be of length ${length}.`)
  }
}

/**
 * Assert that the provided value is a valid string of a length within a given range.
 *
 * @param {string} cipher The cipher string to be validated.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertCipher(cipher: string, message?: string) {
  if (!Object.values(Cipher).includes(cipher as Cipher)) {
    throw new Error(message || `The specified cryptographic suite ${cipher} is not supported.`)
  }
}

/**
 * Assert that the provided array is in ascending order.
 *
 * @param {Array<number>} [array] An array of numbers to be validated.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertAscending(array?: Array<number>, message?: string) {
  if (!array) return
  if (array.some((value, i) => i > 0 && value <= array[i - 1])) {
    throw new Error(message || "The provided array is not in ascending order.")
  }
}

/**
 * Assert that the provided array contains only integers.
 *
 * @param {Array<number>} [array] An array of numbers to be validated.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertInteger(array?: Array<number>, message?: string) {
  if (!array) return
  if (array.some((v) => !Number.isInteger(v))) {
    throw new Error(message || "The provided array MUST be an array of integers.")
  }
}

/**
 * Assert that the provided array contains only non-negative numbers.
 *
 * @param {Array<number>} [array] An array of numbers to be validated.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertNonNegative(array?: Array<number>, message?: string) {
  if (!array) return
  if (array.some((value) => value < 0)) {
    throw new Error(message || "The provided array MUST be an array of non-negative integers.")
  }
}

/**
 * Assert that the provided array contains only numbers within a given range.
 *
 * @param {Array<number>} [array] An array of numbers to be validated.
 * @param {number} [min] The minimum value of the range.
 * @param {number} [max] The maximum value of the range.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertRange(array?: Array<number>, min?: number, max?: number, message?: string) {
  if (!array) return
  if (!min && !max) return
  if (array.some((value) => (min !== undefined && value < min) || (max !== undefined && value > max))) {
    throw new Error(message || `The provided array MUST be an array of integers within the range ${min} to ${max}.`)
  }
}

/**
 * Assert that the provided indexes are valid.
 *
 * @param {Array<number>} [indexes] The indexes to be validated.
 * @param {number} [maxIndex] The maximum index allowed.
 * @param {string} [message] The message to be thrown if the assertion fails.
 */
export function assertIndexes(indexes?: Array<number>, maxIndex?: number, message?: string) {
  assertAscending(indexes, message)
  assertInteger(indexes, message)
  assertNonNegative(indexes, message)
  assertRange(indexes, 0, maxIndex, message)
}

/**
 * Assert that the provided values are the same value.
 *
 * @param {unknown} [a] A value to be compared.
 * @param {unknown} [b] A value to be compared.
 * @param {MessageChannel} [message] The message to be thrown if the assertion fails.
 */
export function assertEquality(a?: unknown, b?: unknown, message?: string) {
  if (!a && !b) return
  if (a !== b) {
    throw new Error(message || `The provided value ${a} is not equal to ${b}.`)
  }
}
