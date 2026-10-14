const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const uploadsDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const db = new Database(path.join(dataDir, 'secure_share.db'));

// Pragmas for durability and performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Initialize database schema
db.exec(`
  CREATE TABLE IF NOT EXISTS shared_files (
    id TEXT PRIMARY KEY,
    owner_token TEXT NOT NULL,
    storage_filename TEXT NOT NULL,
    encrypted_meta TEXT NOT NULL, -- Encrypted filename and MIME type (client-side encrypted)
    file_size INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER, -- UNIX timestamp in ms, or null if strictly download-limited
    max_downloads INTEGER, -- max allowed downloads, null if unlimited
    download_count INTEGER DEFAULT 0,
    is_deleted INTEGER DEFAULT 0,
    has_password INTEGER DEFAULT 0, -- 1 if protected with client-side derived password key
    password_salt TEXT, -- Salt for client-side PBKDF2 if password enabled
    delete_reason TEXT
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT,
    event_type TEXT NOT NULL, -- UPLOADED, ACCESS_VIEWED, DOWNLOADED, ACCESS_DENIED_EXPIRED, ACCESS_DENIED_LIMIT, DELETED_MANUAL, DELETED_AUTO, INVALID_AUTH
    client_ip TEXT,
    user_agent TEXT,
    details TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(file_id) REFERENCES shared_files(id) ON DELETE SET NULL
  );

  CREATE INDEX IF NOT EXISTS idx_shared_files_expires ON shared_files(expires_at);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_file ON audit_logs(file_id);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(created_at DESC);
`);

module.exports = {
  db,
  uploadsDir,
  dataDir
};
