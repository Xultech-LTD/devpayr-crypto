"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptSecure = encryptSecure;
exports.decryptSecure = decryptSecure;
const crypto_1 = __importDefault(require("crypto"));
/**
 * Normalize any key to 32 bytes using SHA-256
 */
function normalizeKey(key) {
    return crypto_1.default.createHash('sha256').update(key).digest();
}
/**
 * Encrypt a string using AES-256-CBC and base64 encoding.
 *
 * @param plaintext - Data to encrypt
 * @param key - Raw key (any string)
 * @returns base64(iv::cipherText)
 */
function encryptSecure(plaintext, key) {
    const iv = crypto_1.default.randomBytes(16);
    const hashedKey = normalizeKey(key);
    const cipher = crypto_1.default.createCipheriv('aes-256-cbc', hashedKey, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const payload = `${iv.toString('base64')}::${encrypted}`;
    return Buffer.from(payload).toString('base64');
}
/**
 * Decrypt a base64(iv::cipherText) string back to plaintext.
 *
 * @param encryptedBase64 - Encrypted payload
 * @param key - Original encryption key
 * @returns Plaintext
 */
function decryptSecure(encryptedBase64, key) {
    const decoded = Buffer.from(encryptedBase64, 'base64').toString();
    const [ivB64, cipherB64] = decoded.split('::');
    if (!ivB64 || !cipherB64) {
        throw new Error("Invalid encrypted format — expected 'iv::cipherText'");
    }
    const iv = Buffer.from(ivB64, 'base64');
    const hashedKey = normalizeKey(key);
    const decipher = crypto_1.default.createDecipheriv('aes-256-cbc', hashedKey, iv);
    let decrypted = decipher.update(cipherB64, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
