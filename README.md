# AegisLock — End-to-End Encrypted File Sharing

> **Zero-Knowledge Architecture with Expiring Links & Tamper-Evident Audit Trails**

---

## 🔒 Security & Architecture Overview

1. **Client-Side Cryptography (Zero-Knowledge)**
   - **Engine**: Browser-native **Web Crypto API** (`SubtleCrypto`).
   - **Cipher**: **AES-GCM 256-bit** with unique 96-bit Initialization Vectors (IV) prepended to the ciphertext.
   - **Key Distribution**: Decryption keys reside entirely in the **URL fragment hash (`#key=...`)**. Browsers never send fragments to servers in HTTP request headers.
   - **Passphrase Protection**: Optional client-side key derivation via **PBKDF2** (100,000 iterations of SHA-256 with 128-bit cryptographic salt).
   - **Encrypted Metadata**: The original filename, MIME type, and file size are encrypted on the client side before submission.

2. **Expiring Links & Burn-After-Reading**
   - **Time-Based Expiration**: 5 minutes (ephemeral), 1 hour, 24 hours, 3 days, 7 days, or unlimited.
   - **Download Limit / Burn-After-Reading**: Enforces single-use downloads (e.g. 1 download burn-after-reading), multi-download limits (3, 5, 10), or unlimited.
   - **Background Cleanup Daemon**: Automatically purges expired ciphertext from disk every 15 seconds.

3. **Tamper-Evident Audit Logs**
   - Tracks all events: `FILE_UPLOADED`, `METADATA_INSPECTED`, `CIPHERTEXT_DOWNLOADED`, `ACCESS_DENIED_EXPIRED`, `ACCESS_DENIED_LIMIT`, `FILE_PURGED_AUTO`, `FILE_MANUALLY_REVOKED`, `CLIENT_DECRYPTION_SUCCESS`.
   - Records UTC timestamp, event type, target file ID, client IP, user agent, and security parameters.
   - Filterable UI table with CSV export.
   - **Owner Revocation Token**: Uploaders receive a secret authorization token allowing immediate manual revocation and dedicated audit inspection.

---

## 🚀 Getting Started

### 1. Start the Server
```bash
npm start
```
The application will launch on `http://localhost:3000`.

### 2. Sharing a File
1. Open `http://localhost:3000` in your browser.
2. Select or drag & drop any file (up to 100 MB).
3. Choose your **Expiration Time** (e.g., 1 Hour) and **Download Limit** (e.g., *1 Download - Burn after reading*).
4. (Optional) Set an additional passphrase.
5. Click **Encrypt & Generate Secure Link**.
6. Copy the generated link (which includes `#file=<ID>&key=<KEY>`) and send it to your recipient.

### 3. Decrypting & Downloading
1. Open the shareable link in any browser.
2. The browser automatically inspects the link validity and downloads remaining.
3. Click **Download Ciphertext & Decrypt in Browser**.
4. The ciphertext stream is decrypted locally using Web Crypto API and saved to disk.

### 4. Viewing Audit Logs
- Navigate to the **Audit Logs** tab to view real-time security events, download counts, and export the logs to CSV.

---

## 📁 Project Structure

```
d:/File sharing/
├── server/
│   ├── index.js      # Express API server & cleanup daemon
│   ├── db.js         # SQLite database schema (WAL mode)
│   └── audit.js      # Audit trail logger & query engine
├── public/
│   ├── index.html    # Modern dark glassmorphic interface
│   ├── crypto.js     # Web Crypto API AES-GCM & PBKDF2 engine
│   ├── app.js        # Frontend controller & UI interactions
│   └── style.css     # Premium UI styling and animations
├── test_api.js       # Integration verification script
└── package.json      # Dependencies and scripts
```
