const { encryptSecure, decryptSecure } = require('./index');

const key = 'sk_devpayr_test123';
const message = 'License key 9X2A2-F3DEV-4YZ-P1!';

const encrypted = encryptSecure(message, key);
console.log('Encrypted:', encrypted);

const decrypted = decryptSecure(encrypted, key);
console.log('Decrypted:', decrypted);
