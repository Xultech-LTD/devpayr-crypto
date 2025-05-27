/**
 * Encrypt a string using AES-256-CBC and base64 encoding.
 *
 * @param plaintext - Data to encrypt
 * @param key - Raw key (any string)
 * @returns base64(iv::cipherText)
 */
export declare function encryptSecure(plaintext: string, key: string): string;
/**
 * Decrypt a base64(iv::cipherText) string back to plaintext.
 *
 * @param encryptedBase64 - Encrypted payload
 * @param key - Original encryption key
 * @returns Plaintext
 */
export declare function decryptSecure(encryptedBase64: string, key: string): string;
