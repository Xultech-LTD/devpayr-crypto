# DevPayr Crypto

Secure, Laravel-compatible encryption and decryption using AES-256-CBC for Node.js.  
This package is designed to match the encryption scheme used by the [DevPayr](https://devpayr.com) platform, enabling safe communication between Node.js clients and the DevPayr server.

---

## ✨ Features

- 🔐 AES-256-CBC encryption with random IV
- 🔑 Accepts any key and normalizes to 32-byte (via SHA-256)
- 📦 Base64-encoded output compatible with Laravel `encrypt_secure()`/`decrypt_secure()`
- ⚡ Lightweight and dependency-free (uses Node's built-in `crypto`)

---

## 📦 Installation

```bash
npm install @xultech/devpayr-crypto
```

## 🚀 Usage

### 1. Encrypt a string

```js
const { encryptSecure } = require('@xultech/devpayr-crypto');

const key = 'sk_devpayr_test123';
const plaintext = 'Hello, DevPayr!';

const encrypted = encryptSecure(plaintext, key);
console.log(encrypted); // Outputs: base64(iv::cipherText)
```

### 2. Decrypt an encrypted string

```js
const { decryptSecure } = require('@xultech/devpayr-crypto');

const encrypted = '...'; // base64 string from `encryptSecure`
const key = 'sk_devpayr_test123';

const decrypted = decryptSecure(encrypted, key);
console.log(decrypted); // Outputs: Hello, DevPayr!
```

## How It Works

- Uses AES-256-CBC with a 16-byte random IV.

- Keys are normalized to 32 bytes using SHA-256 (to meet AES-256 requirements).

- Final format is: base64(iv::cipherText) — fully compatible with Laravel backend.
  
### 📄 Example

```js
const { encryptSecure, decryptSecure } = require('@xultech/devpayr-crypto');

const key = 'sk_devpayr_test123';
const original = 'API key: ABC123';

const encrypted = encryptSecure(original, key);
console.log('Encrypted:', encrypted);

const decrypted = decryptSecure(encrypted, key);
console.log('Decrypted:', decrypted);
```

## 📖 License

MIT © DevPayr