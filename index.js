// index.js

const crypto = require('crypto');

/**
 * Normalize any key to 32 bytes using SHA-256
 */
function normalizeKey(key) {
    return crypto.createHash('sha256').update(key).digest();
}

/**
 * Encrypt a string using AES-256-CBC and base64 encoding.
 *
 * @param {string} plaintext - Data to encrypt
 * @param {string} key - Raw key (any string)
 * @returns {string} - base64(iv::ciphertext)
 */
function encryptSecure(plaintext, key) {
    const iv = crypto.randomBytes(16);
    const hashedKey = normalizeKey(key);

    const cipher = crypto.createCipheriv('aes-256-cbc', hashedKey, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    const payload = `${iv.toString('base64')}::${encrypted}`;
    return Buffer.from(payload).toString('base64');
}

/**
 * Decrypt a base64(iv::ciphertext) string back to plaintext.
 *
 * @param {string} encryptedBase64
 * @param {string} key
 * @returns {string}
 */
function decryptSecure(encryptedBase64, key) {
    const decoded = Buffer.from(encryptedBase64, 'base64').toString();
    const [ivB64, cipherB64] = decoded.split('::');

    if (!ivB64 || !cipherB64) {
        throw new Error("Invalid encrypted format — expected 'iv::cipherText'");
    }

    const iv = Buffer.from(ivB64, 'base64');
    const hashedKey = normalizeKey(key);

    const decipher = crypto.createDecipheriv('aes-256-cbc', hashedKey, iv);
    let decrypted = decipher.update(cipherB64, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

module.exports = {
    encryptSecure,
    decryptSecure,
};
