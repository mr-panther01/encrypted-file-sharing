/**
 * E2EE Cryptography Engine using Browser Native Web Crypto API
 * Implements:
 * - AES-GCM 256-bit for bulk file & metadata encryption
 * - PBKDF2 with 100,000 SHA-256 iterations for optional passphrase strengthening
 * - Zero-knowledge key generation: Secret keys are stored in the URL Fragment (#)
 *   which is NEVER sent to the server in HTTP requests.
 */

class CryptoEngine {
  // Convert ArrayBuffer to Base64URL
  static bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // Convert Base64URL to ArrayBuffer
  static base64UrlToBuffer(base64Url) {
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // Generate a cryptographically secure random 256-bit AES-GCM Key
  static async generateMasterKey() {
    return await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable
      ['encrypt', 'decrypt']
    );
  }

  // Export CryptoKey to raw Base64Url string for the URL fragment
  static async exportKey(cryptoKey) {
    const raw = await window.crypto.subtle.exportKey('raw', cryptoKey);
    return this.bufferToBase64Url(raw);
  }

  // Import CryptoKey from Base64Url string
  static async importKey(keyString) {
    const raw = this.base64UrlToBuffer(keyString);
    return await window.crypto.subtle.importKey(
      'raw',
      raw,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  // Derive key from passphrase using PBKDF2
  static async deriveKeyFromPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // Generate random Initialization Vector (96-bit for AES-GCM)
  static generateIV() {
    return window.crypto.getRandomValues(new Uint8Array(12));
  }

  // Generate random Salt (128-bit)
  static generateSalt() {
    return window.crypto.getRandomValues(new Uint8Array(16));
  }

  /**
   * Encrypt File Content and Metadata
   * @param {File} file 
   * @param {string} [passphrase] - Optional extra password
   * @returns {Promise<{ ciphertextBlob: Blob, encryptedMeta: string, keyHashFragment: string, salt: string }>}
   */
  static async encryptFile(file, passphrase = '') {
    // 1. Generate master AES-256 key
    const masterKey = await this.generateMasterKey();
    const rawKeyString = await this.exportKey(masterKey);

    let activeKey = masterKey;
    let saltBase64 = null;

    // If passphrase is provided, we double-encrypt or derive key
    if (passphrase && passphrase.trim().length > 0) {
      const salt = this.generateSalt();
      activeKey = await this.deriveKeyFromPassword(passphrase, salt);
      saltBase64 = this.bufferToBase64Url(salt);
    }

    // 2. Read file ArrayBuffer
    const fileBuffer = await file.arrayBuffer();

    // 3. Encrypt file data
    const fileIv = this.generateIV();
    const encryptedFileBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: fileIv },
      activeKey,
      fileBuffer
    );

    // Prepend the 12-byte IV to the ciphertext payload
    const combinedFileBuffer = new Uint8Array(fileIv.byteLength + encryptedFileBuffer.byteLength);
    combinedFileBuffer.set(fileIv, 0);
    combinedFileBuffer.set(new Uint8Array(encryptedFileBuffer), fileIv.byteLength);

    const ciphertextBlob = new Blob([combinedFileBuffer], { type: 'application/octet-stream' });

    // 4. Encrypt Metadata (Original File Name, MIME type, size)
    const metaIv = this.generateIV();
    const metaObj = {
      name: file.name,
      type: file.type || 'application/octet-stream',
      size: file.size,
      lastModified: file.lastModified
    };
    const metaBytes = new TextEncoder().encode(JSON.stringify(metaObj));
    const encryptedMetaBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: metaIv },
      activeKey,
      metaBytes
    );

    const encryptedMetaString = JSON.stringify({
      iv: this.bufferToBase64Url(metaIv),
      data: this.bufferToBase64Url(encryptedMetaBuffer)
    });

    return {
      ciphertextBlob,
      encryptedMeta: encryptedMetaString,
      keyHashFragment: rawKeyString,
      salt: saltBase64,
      hasPassword: Boolean(passphrase && passphrase.trim().length > 0)
    };
  }

  /**
   * Decrypt Metadata
   */
  static async decryptMeta(encryptedMetaJson, keyString, passphrase = '', saltBase64 = null) {
    let key;
    if (passphrase && saltBase64) {
      const salt = new Uint8Array(this.base64UrlToBuffer(saltBase64));
      key = await this.deriveKeyFromPassword(passphrase, salt);
    } else {
      key = await this.importKey(keyString);
    }

    const { iv, data } = JSON.parse(encryptedMetaJson);
    const ivBuffer = this.base64UrlToBuffer(iv);
    const dataBuffer = this.base64UrlToBuffer(data);

    const decryptedMetaBytes = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(ivBuffer) },
      key,
      dataBuffer
    );

    const metaText = new TextDecoder().decode(decryptedMetaBytes);
    return JSON.parse(metaText);
  }

  /**
   * Decrypt File Payload ArrayBuffer
   */
  static async decryptFile(encryptedArrayBuffer, keyString, passphrase = '', saltBase64 = null) {
    let key;
    if (passphrase && saltBase64) {
      const salt = new Uint8Array(this.base64UrlToBuffer(saltBase64));
      key = await this.deriveKeyFromPassword(passphrase, salt);
    } else {
      key = await this.importKey(keyString);
    }

    // Extract 12-byte IV from beginning
    const fullBytes = new Uint8Array(encryptedArrayBuffer);
    const iv = fullBytes.slice(0, 12);
    const ciphertext = fullBytes.slice(12);

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );

    return decryptedBuffer;
  }
}

// Make accessible to browser window
window.CryptoEngine = CryptoEngine;
