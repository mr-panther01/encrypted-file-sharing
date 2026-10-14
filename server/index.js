const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const { db, uploadsDir } = require('./db');
const { logEvent, getAuditLogs } = require('./audit');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// Configure Multer for encrypted payload storage
// Note: The payload is ALREADY ciphertext encrypted by client browser
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = uuidv4() + '.enc';
    cb(null, uniqueSuffix);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 } // 100 MB max encrypted payload
});

// Periodic cleanup of expired and deleted files
function cleanupExpiredFiles() {
  const now = Date.now();
  try {
    const expiredFiles = db.prepare(`
      SELECT id, storage_filename, expires_at, max_downloads, download_count 
      FROM shared_files 
      WHERE is_deleted = 0 AND (
        (expires_at IS NOT NULL AND expires_at <= ?) OR
        (max_downloads IS NOT NULL AND download_count >= max_downloads)
      )
    `).all(now);

    for (const file of expiredFiles) {
      const reason = (file.expires_at && file.expires_at <= now) ? 'TIME_EXPIRED' : 'DOWNLOAD_LIMIT_REACHED';
      const filePath = path.join(uploadsDir, file.storage_filename);
      if (fs.existsSync(filePath)) {
        try {
          fs.unlinkSync(filePath);
        } catch (e) {
          console.error(`Error deleting file ${file.storage_filename}:`, e);
        }
      }

      db.prepare(`UPDATE shared_files SET is_deleted = 1, delete_reason = ? WHERE id = ?`).run(reason, file.id);
      
      // Pseudo request object for system event
      logEvent(file.id, 'FILE_PURGED_AUTO', { headers: {}, socket: { remoteAddress: '127.0.0.1' } }, {
        reason,
        downloadCount: file.download_count,
        maxDownloads: file.max_downloads
      });
    }
  } catch (err) {
    console.error('Error during cleanup routine:', err);
  }
}

// Run cleanup every 15 seconds
setInterval(cleanupExpiredFiles, 15000);

// API: Upload Encrypted File
app.post('/api/upload', upload.single('ciphertextBlob'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No encrypted payload provided' });
    }

    const {
      encryptedMeta, // Client-side encrypted JSON string (e.g. { name, size, type, iv, salt })
      expiresInMinutes,
      maxDownloads,
      hasPassword,
      passwordSalt
    } = req.body;

    if (!encryptedMeta) {
      // Remove uploaded file if metadata is missing
      if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Encrypted metadata required' });
    }

    const fileId = uuidv4();
    const ownerToken = uuidv4(); // Secret token returned only to uploader to manage/delete/view private logs
    const createdAt = Date.now();
    
    let expiresAt = null;
    const minutes = parseInt(expiresInMinutes, 10);
    if (!isNaN(minutes) && minutes > 0) {
      expiresAt = createdAt + (minutes * 60 * 1000);
    }

    const maxDl = parseInt(maxDownloads, 10);
    const downloadLimit = (!isNaN(maxDl) && maxDl > 0) ? maxDl : null;

    db.prepare(`
      INSERT INTO shared_files (
        id, owner_token, storage_filename, encrypted_meta, file_size, 
        created_at, expires_at, max_downloads, download_count, 
        is_deleted, has_password, password_salt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
    `).run(
      fileId,
      ownerToken,
      req.file.filename,
      encryptedMeta,
      req.file.size,
      createdAt,
      expiresAt,
      downloadLimit,
      hasPassword === 'true' || hasPassword === true ? 1 : 0,
      passwordSalt || null
    );

    logEvent(fileId, 'FILE_UPLOADED', req, {
      fileSize: req.file.size,
      expiresAt,
      maxDownloads: downloadLimit,
      hasPassword: Boolean(hasPassword)
    });

    return res.status(201).json({
      success: true,
      fileId,
      ownerToken,
      expiresAt,
      maxDownloads: downloadLimit
    });
  } catch (err) {
    console.error('Upload error:', err);
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    return res.status(500).json({ error: 'Server error processing encrypted upload' });
  }
});

// API: Get File Metadata (Public / Receiver endpoint)
app.get('/api/file/:id/meta', (req, res) => {
  try {
    const { id } = req.params;
    const file = db.prepare('SELECT * FROM shared_files WHERE id = ?').get(id);

    if (!file) {
      logEvent(id, 'ACCESS_NOT_FOUND', req);
      return res.status(404).json({ error: 'File not found or has been removed' });
    }

    const now = Date.now();
    if (file.is_deleted) {
      logEvent(id, 'ACCESS_DENIED_DELETED', req, { reason: file.delete_reason });
      return res.status(410).json({
        error: 'File is no longer accessible',
        reason: file.delete_reason || 'DELETED'
      });
    }

    if (file.expires_at && file.expires_at <= now) {
      cleanupExpiredFiles();
      logEvent(id, 'ACCESS_DENIED_EXPIRED', req);
      return res.status(410).json({ error: 'This secure link has expired', reason: 'TIME_EXPIRED' });
    }

    if (file.max_downloads && file.download_count >= file.max_downloads) {
      cleanupExpiredFiles();
      logEvent(id, 'ACCESS_DENIED_LIMIT', req);
      return res.status(410).json({ error: 'Download limit has been reached', reason: 'DOWNLOAD_LIMIT_REACHED' });
    }

    logEvent(id, 'METADATA_INSPECTED', req);

    res.json({
      id: file.id,
      encryptedMeta: file.encrypted_meta,
      fileSize: file.file_size,
      createdAt: file.created_at,
      expiresAt: file.expires_at,
      downloadCount: file.download_count,
      maxDownloads: file.max_downloads,
      hasPassword: Boolean(file.has_password),
      passwordSalt: file.password_salt
    });
  } catch (err) {
    console.error('Meta retrieval error:', err);
    res.status(500).json({ error: 'Failed to retrieve file info' });
  }
});

// API: Download Encrypted Ciphertext Blob
app.get('/api/file/:id/download', (req, res) => {
  try {
    const { id } = req.params;
    const file = db.prepare('SELECT * FROM shared_files WHERE id = ?').get(id);

    if (!file) {
      logEvent(id, 'DOWNLOAD_FAILED_NOT_FOUND', req);
      return res.status(404).json({ error: 'File not found' });
    }

    const now = Date.now();
    if (file.is_deleted) {
      logEvent(id, 'DOWNLOAD_FAILED_DELETED', req, { reason: file.delete_reason });
      return res.status(410).json({ error: 'File is no longer available', reason: file.delete_reason });
    }

    if (file.expires_at && file.expires_at <= now) {
      cleanupExpiredFiles();
      logEvent(id, 'DOWNLOAD_FAILED_EXPIRED', req);
      return res.status(410).json({ error: 'This file link has expired', reason: 'TIME_EXPIRED' });
    }

    if (file.max_downloads && file.download_count >= file.max_downloads) {
      cleanupExpiredFiles();
      logEvent(id, 'DOWNLOAD_FAILED_LIMIT', req);
      return res.status(410).json({ error: 'Download limit reached', reason: 'DOWNLOAD_LIMIT_REACHED' });
    }

    const filePath = path.join(uploadsDir, file.storage_filename);
    if (!fs.existsSync(filePath)) {
      logEvent(id, 'DOWNLOAD_FAILED_MISSING_BLOB', req);
      return res.status(404).json({ error: 'Physical encrypted payload missing' });
    }

    // Increment download count
    const newCount = file.download_count + 1;
    db.prepare('UPDATE shared_files SET download_count = ? WHERE id = ?').run(newCount, id);

    logEvent(id, 'CIPHERTEXT_DOWNLOADED', req, {
      currentDownloadNumber: newCount,
      maxDownloads: file.max_downloads
    });

    // Check if burn-after-reading or reached limit immediately
    if (file.max_downloads && newCount >= file.max_downloads) {
      setTimeout(cleanupExpiredFiles, 1000);
    }

    // Set headers for raw binary ciphertext delivery
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="encrypted_${file.id}.bin"`);
    res.setHeader('X-Secure-Download-Count', newCount);
    res.setHeader('X-Secure-Max-Downloads', file.max_downloads || 'unlimited');

    const readStream = fs.createReadStream(filePath);
    readStream.pipe(res);
  } catch (err) {
    console.error('Download stream error:', err);
    res.status(500).json({ error: 'Internal error streaming encrypted file' });
  }
});

// API: Manual File Deletion (Owner only)
app.delete('/api/file/:id', (req, res) => {
  try {
    const { id } = req.params;
    const { ownerToken } = req.body || req.query;

    if (!ownerToken) {
      logEvent(id, 'DELETE_FAILED_NO_TOKEN', req);
      return res.status(401).json({ error: 'Owner authorization token required' });
    }

    const file = db.prepare('SELECT * FROM shared_files WHERE id = ?').get(id);
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    if (file.owner_token !== ownerToken) {
      logEvent(id, 'DELETE_FAILED_BAD_TOKEN', req);
      return res.status(403).json({ error: 'Invalid owner authorization token' });
    }

    const filePath = path.join(uploadsDir, file.storage_filename);
    if (fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
      } catch (e) {
        console.error('Failed to unlink file on delete:', e);
      }
    }

    db.prepare('UPDATE shared_files SET is_deleted = 1, delete_reason = ? WHERE id = ?').run('MANUAL_REVOCATION', id);
    logEvent(id, 'FILE_MANUALLY_REVOKED', req, { triggeredBy: 'OWNER' });

    res.json({ success: true, message: 'File and encrypted data permanently destroyed.' });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Failed to revoke file' });
  }
});

// API: Audit Log Endpoint
// Can retrieve all system logs or filter by fileId (owner restricted or public system view)
app.get('/api/audit-logs', (req, res) => {
  try {
    const { fileId, eventType, limit, ownerToken } = req.query;

    // If querying specific file, verify ownerToken if file exists
    if (fileId && ownerToken) {
      const file = db.prepare('SELECT owner_token FROM shared_files WHERE id = ?').get(fileId);
      if (file && file.owner_token !== ownerToken) {
        return res.status(403).json({ error: 'Invalid owner authorization for detailed file audit logs' });
      }
    }

    const logs = getAuditLogs({
      fileId: fileId || undefined,
      eventType: eventType || undefined,
      limit: limit ? parseInt(limit, 10) : 100
    });

    res.json({ logs });
  } catch (err) {
    console.error('Audit query error:', err);
    res.status(500).json({ error: 'Failed to query audit logs' });
  }
});

// API: Client Decryption Report (Client reports that decryption succeeded or failed)
app.post('/api/file/:id/report-crypto', (req, res) => {
  try {
    const { id } = req.params;
    const { success, errorReason } = req.body;

    if (success) {
      logEvent(id, 'CLIENT_DECRYPTION_SUCCESS', req);
    } else {
      logEvent(id, 'CLIENT_DECRYPTION_FAILED', req, { reason: errorReason || 'Wrong key or corrupted ciphertext' });
    }

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Logging report failed' });
  }
});

// API: System Statistics for Dashboard
app.get('/api/stats', (req, res) => {
  try {
    const totalFiles = db.prepare('SELECT COUNT(*) as count FROM shared_files').get().count;
    const activeFiles = db.prepare('SELECT COUNT(*) as count FROM shared_files WHERE is_deleted = 0').get().count;
    const totalDownloads = db.prepare('SELECT SUM(download_count) as count FROM shared_files').get().count || 0;
    const totalAuditEvents = db.prepare('SELECT COUNT(*) as count FROM audit_logs').get().count;

    res.json({
      totalFiles,
      activeFiles,
      totalDownloads,
      totalAuditEvents
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

app.listen(PORT, () => {
  console.log(`🔒 E2EE File Sharing Server running on http://localhost:${PORT}`);
});
