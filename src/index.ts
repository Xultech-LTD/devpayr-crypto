import crypto from 'crypto';

/**
 * Normalize any key to 32 bytes using SHA-256
 */
function normalizeKey(key: string): Buffer {
  return crypto.createHash('sha256').update(key).digest();
}

/**
 * Encrypt a string using AES-256-CBC and base64 encoding.
 *
 * @param plaintext - Data to encrypt
 * @param key - Raw key (any string)
 * @returns base64(iv::cipherText)
 */
export function encryptSecure(plaintext: string, key: string): string {
  const iv = crypto.randomBytes(16);
  const hashedKey = normalizeKey(key);

  const cipher = crypto.createCipheriv('aes-256-cbc', hashedKey, iv);
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
export function decryptSecure(encryptedBase64: string, key: string): string {
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
