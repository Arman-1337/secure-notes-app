/**
 * Secure Note Sharing - Crypto Utilities
 * 
 * This module provides client-side encryption/decryption using:
 * - AES-GCM 256-bit encryption
 * - PBKDF2 for key derivation from passwords
 * - Web Crypto API (browser native)
 * - Base64 encoding for data transmission
 */

// Configuration constants
const CRYPTO_CONFIG = {
    // AES-GCM parameters
    AES_KEY_LENGTH: 256,        // 256-bit key
    AES_IV_LENGTH: 96,          // 96-bit IV (12 bytes) - recommended for GCM
    
    // PBKDF2 parameters
    PBKDF2_ITERATIONS: 100000,  // 100k iterations for good security/performance balance
    PBKDF2_SALT_LENGTH: 128,    // 128-bit salt (16 bytes)
    
    // Hash algorithm for PBKDF2
    HASH_ALGORITHM: 'SHA-256'
};

/**
 * Convert ArrayBuffer to Base64 string
 * @param {ArrayBuffer} buffer - The buffer to convert
 * @returns {string} Base64 encoded string
 */
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Convert Base64 string to ArrayBuffer
 * @param {string} base64 - Base64 encoded string
 * @returns {ArrayBuffer} The decoded buffer
 */
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Generate a cryptographically secure random buffer
 * @param {number} byteLength - Length in bytes
 * @returns {ArrayBuffer} Random buffer
 */
function generateRandomBuffer(byteLength) {
    const array = new Uint8Array(byteLength);
    crypto.getRandomValues(array);
    return array.buffer;
}

/**
 * Derive an AES-GCM key from password using PBKDF2
 * @param {string} password - User password
 * @param {ArrayBuffer} salt - Salt for key derivation
 * @returns {Promise<CryptoKey>} Derived AES key
 */
async function generateKeyFromPassword(password, salt) {
    // Convert password to ArrayBuffer
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    
    // Import password as base key for PBKDF2
    const baseKey = await crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        { name: 'PBKDF2' },
        false, // not extractable
        ['deriveKey']
    );
    
    // Derive AES-GCM key using PBKDF2
    const derivedKey = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: CRYPTO_CONFIG.PBKDF2_ITERATIONS,
            hash: CRYPTO_CONFIG.HASH_ALGORITHM
        },
        baseKey,
        {
            name: 'AES-GCM',
            length: CRYPTO_CONFIG.AES_KEY_LENGTH
        },
        false, // not extractable
        ['encrypt', 'decrypt']
    );
    
    return derivedKey;
}

/**
 * Encrypt a plaintext note using AES-GCM
 * @param {string} plaintext - The note to encrypt
 * @param {string} password - User password
 * @returns {Promise<{ciphertext: string, iv: string, salt: string}>} Encrypted data
 */
async function encryptNote(plaintext, password) {
    try {
        // Generate random salt and IV
        const salt = generateRandomBuffer(CRYPTO_CONFIG.PBKDF2_SALT_LENGTH / 8);
        const iv = generateRandomBuffer(CRYPTO_CONFIG.AES_IV_LENGTH / 8);
        
        // Derive key from password
        const key = await generateKeyFromPassword(password, salt);
        
        // Convert plaintext to ArrayBuffer
        const encoder = new TextEncoder();
        const plaintextBuffer = encoder.encode(plaintext);
        
        // Encrypt using AES-GCM
        const ciphertextBuffer = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128 // 128-bit authentication tag
            },
            key,
            plaintextBuffer
        );
        
        // Return Base64-encoded components
        return {
            ciphertext: arrayBufferToBase64(ciphertextBuffer),
            iv: arrayBufferToBase64(iv),
            salt: arrayBufferToBase64(salt)
        };
        
    } catch (error) {
        console.error('Encryption failed:', error);
        throw new Error('Failed to encrypt note: ' + error.message);
    }
}

/**
 * Decrypt a ciphertext using AES-GCM
 * @param {string} ciphertextBase64 - Base64 encoded ciphertext
 * @param {string} ivBase64 - Base64 encoded IV
 * @param {string} saltBase64 - Base64 encoded salt
 * @param {string} password - User password
 * @returns {Promise<string>} Decrypted plaintext
 */
async function decryptNote(ciphertextBase64, ivBase64, saltBase64, password) {
    try {
        // Convert Base64 strings back to ArrayBuffers
        const ciphertextBuffer = base64ToArrayBuffer(ciphertextBase64);
        const iv = base64ToArrayBuffer(ivBase64);
        const salt = base64ToArrayBuffer(saltBase64);
        
        // Derive key from password using same salt
        const key = await generateKeyFromPassword(password, salt);
        
        // Decrypt using AES-GCM
        const decryptedBuffer = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            key,
            ciphertextBuffer
        );
        
        // Convert decrypted buffer back to string
        const decoder = new TextDecoder();
        const plaintext = decoder.decode(decryptedBuffer);
        
        return plaintext;
        
    } catch (error) {
        console.error('Decryption failed:', error);
        
        // Provide more specific error messages
        if (error.name === 'OperationError') {
            throw new Error('Incorrect password or corrupted data');
        } else {
            throw new Error('Failed to decrypt note: ' + error.message);
        }
    }
}

/**
 * Validate that the browser supports required crypto features
 * @returns {boolean} True if crypto features are available
 */
function isCryptoSupported() {
    return !!(
        window.crypto &&
        window.crypto.subtle &&
        window.crypto.getRandomValues &&
        typeof TextEncoder !== 'undefined' &&
        typeof TextDecoder !== 'undefined'
    );
}

// Check crypto support on module load
if (!isCryptoSupported()) {
    console.error('Required crypto features are not supported in this browser');
    alert('This browser does not support the required cryptographic features. Please use a modern browser with Web Crypto API support.');
}

// Export functions (if using modules) or make globally available
if (typeof module !== 'undefined' && module.exports) {
    // Node.js/CommonJS environment
    module.exports = {
        generateKeyFromPassword,
        encryptNote,
        decryptNote,
        arrayBufferToBase64,
        base64ToArrayBuffer,
        isCryptoSupported
    };
} else {
    // Browser global environment
    window.CryptoUtils = {
        generateKeyFromPassword,
        encryptNote,
        decryptNote,
        arrayBufferToBase64,
        base64ToArrayBuffer,
        isCryptoSupported
    };
}