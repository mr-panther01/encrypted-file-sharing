// Global Application State
let selectedFile = null;
let currentCreatedFile = null; // { fileId, ownerToken, secretKey, fullUrl }
let activeReceiveFileMeta = null;
let activeReceiveFileId = null;
let activeReceiveKey = null;

// Tab Switching
function switchTab(tabId) {
  document.getElementById('viewShare').style.display = tabId === 'share' ? 'block' : 'none';
  document.getElementById('viewReceive').style.display = tabId === 'receive' ? 'block' : 'none';
  document.getElementById('viewAudit').style.display = tabId === 'audit' ? 'block' : 'none';

  document.getElementById('tabShare').classList.toggle('active', tabId === 'share');
  document.getElementById('tabReceive').classList.toggle('active', tabId === 'receive');
  document.getElementById('tabAudit').classList.toggle('active', tabId === 'audit');

  if (tabId === 'audit') {
    fetchAuditStats();
    fetchAuditLogs();
  }
}

// Show Toast
function showToast(msg, icon = '🔒') {
  const toast = document.getElementById('toast');
  const toastMsg = document.getElementById('toastMsg');
  const toastIcon = document.getElementById('toastIcon');

  toastMsg.textContent = msg;
  toastIcon.textContent = icon;
  toast.style.display = 'flex';

  setTimeout(() => {
    toast.style.display = 'none';
  }, 3500);
}

// File Drag & Drop Handler
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');

['dragenter', 'dragover'].forEach(eventName => {
  dropzone.addEventListener(eventName, (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  }, false);
});

['dragleave', 'drop'].forEach(eventName => {
  dropzone.addEventListener(eventName, (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
  }, false);
});

dropzone.addEventListener('drop', (e) => {
  const dt = e.dataTransfer;
  const files = dt.files;
  if (files && files.length > 0) {
    handleFileSelection(files[0]);
  }
});

fileInput.addEventListener('change', (e) => {
  if (e.target.files && e.target.files.length > 0) {
    handleFileSelection(e.target.files[0]);
  }
});

function handleFileSelection(file) {
  selectedFile = file;
  document.getElementById('fileSelectedBox').style.display = 'flex';
  document.getElementById('dropzone').style.display = 'none';

  const ext = file.name.split('.').pop().toUpperCase() || 'FILE';
  document.getElementById('fileTypeIcon').textContent = ext.substring(0, 4);
  document.getElementById('selectedFileName').textContent = file.name;
  document.getElementById('selectedFileSize').textContent = formatBytes(file.size);

  document.getElementById('btnEncryptUpload').disabled = false;
}

function clearSelectedFile() {
  selectedFile = null;
  fileInput.value = '';
  document.getElementById('fileSelectedBox').style.display = 'none';
  document.getElementById('dropzone').style.display = 'block';
  document.getElementById('btnEncryptUpload').disabled = true;
}

function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Main Encryption and Upload Workflow
async function handleEncryptAndUpload() {
  if (!selectedFile) return;

  const btn = document.getElementById('btnEncryptUpload');
  const progressCard = document.getElementById('progressCard');
  const progressStatus = document.getElementById('progressStatusText');
  const progressBarFill = document.getElementById('progressBarFill');
  const progressPercent = document.getElementById('progressPercent');

  btn.disabled = true;
  progressCard.style.display = 'block';
  progressBarFill.style.width = '15%';
  progressPercent.textContent = '15%';
  progressStatus.textContent = 'Generating 256-bit AES-GCM Key...';

  try {
    const passphrase = document.getElementById('passphraseInput').value;
    const expiresInMinutes = document.getElementById('expirationSelect').value;
    const maxDownloads = document.getElementById('downloadsSelect').value;

    await new Promise(r => setTimeout(r, 150)); // UI paint

    progressBarFill.style.width = '40%';
    progressPercent.textContent = '40%';
    progressStatus.textContent = 'Encrypting file & metadata with Web Crypto API...';

    // 1. Perform Client-Side Encryption
    const { ciphertextBlob, encryptedMeta, keyHashFragment, salt, hasPassword } = 
      await window.CryptoEngine.encryptFile(selectedFile, passphrase);

    progressBarFill.style.width = '70%';
    progressPercent.textContent = '70%';
    progressStatus.textContent = 'Uploading encrypted ciphertext blob to server...';

    // 2. Prepare FormData payload
    const formData = new FormData();
    formData.append('ciphertextBlob', ciphertextBlob, 'encrypted.bin');
    formData.append('encryptedMeta', encryptedMeta);
    formData.append('expiresInMinutes', expiresInMinutes === 'never' ? '' : expiresInMinutes);
    formData.append('maxDownloads', maxDownloads === 'unlimited' ? '' : maxDownloads);
    formData.append('hasPassword', hasPassword ? 'true' : 'false');
    if (salt) {
      formData.append('passwordSalt', salt);
    }

    // 3. Post to Server
    const response = await fetch('/api/upload', {
      method: 'POST',
      body: formData
    });

    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || 'Failed to upload encrypted file');
    }

    progressBarFill.style.width = '100%';
    progressPercent.textContent = '100%';
    progressStatus.textContent = 'Complete! Zero-knowledge link generated.';

    // 4. Construct Share Link with Key in URL Fragment (#)
    // URL fragment is never transmitted in HTTP requests, keeping server zero-knowledge
    const shareableUrl = `${window.location.origin}/#file=${result.fileId}&key=${keyHashFragment}`;

    currentCreatedFile = {
      fileId: result.fileId,
      ownerToken: result.ownerToken,
      secretKey: keyHashFragment,
      fullUrl: shareableUrl
    };

    // Store created file in local storage so user can track files they shared
    saveUserSharedFile(result.fileId, selectedFile.name, result.ownerToken, shareableUrl);

    // 5. Display Result
    document.getElementById('shareableLinkInput').value = shareableUrl;
    document.getElementById('ownerTokenDisplay').textContent = result.ownerToken;
    document.getElementById('resultCard').style.display = 'block';

    showToast('Encrypted successfully! Link generated.', '🛡️');
  } catch (err) {
    console.error('Encryption / upload failed:', err);
    alert('Error during encryption: ' + err.message);
  } finally {
    btn.disabled = false;
  }
}

function copyShareLink() {
  const linkInput = document.getElementById('shareableLinkInput');
  linkInput.select();
  navigator.clipboard.writeText(linkInput.value);
  showToast('Link copied to clipboard!', '📋');
}

// Save to LocalStorage for easy sender tracking
function saveUserSharedFile(id, name, ownerToken, url) {
  const list = JSON.parse(localStorage.getItem('aegis_my_shares') || '[]');
  list.unshift({ id, name, ownerToken, url, date: Date.now() });
  localStorage.setItem('aegis_my_shares', JSON.stringify(list.slice(0, 20)));
}

// Revoke Current File
async function revokeCurrentFile() {
  if (!currentCreatedFile) return;
  if (!confirm('Are you sure you want to permanently revoke and purge this file from the server?')) return;

  try {
    const res = await fetch(`/api/file/${currentCreatedFile.fileId}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ownerToken: currentCreatedFile.ownerToken })
    });
    const data = await res.json();
    if (res.ok) {
      showToast('File securely destroyed!', '🔥');
      document.getElementById('resultCard').style.display = 'none';
      clearSelectedFile();
    } else {
      alert(data.error || 'Revocation failed');
    }
  } catch (e) {
    alert('Revocation error: ' + e.message);
  }
}

function viewFileAuditLogs() {
  if (!currentCreatedFile) return;
  switchTab('audit');
  fetchAuditLogs(currentCreatedFile.fileId);
}

// -------------------------------------------------------------
// RECEIVE / DECRYPT CONTROLS
// -------------------------------------------------------------

async function inspectUrlParameters() {
  const hash = window.location.hash.substring(1); // remove '#'
  if (!hash) return;

  const params = new URLSearchParams(hash);
  const fileId = params.get('file');
  const key = params.get('key');

  if (fileId) {
    switchTab('receive');
    activeReceiveFileId = fileId;
    activeReceiveKey = key;
    await loadReceiveFile(fileId, key);
  }
}

async function loadReceiveFile(fileId, key) {
  const title = document.getElementById('receiveTitle');
  const subtitle = document.getElementById('receiveSubtitle');
  const badgeActive = document.getElementById('badgeActive');
  const badgeExpired = document.getElementById('badgeExpired');
  const errorBox = document.getElementById('receiveErrorMessage');
  const passphraseBlock = document.getElementById('receivePassphraseBlock');

  errorBox.style.display = 'none';

  try {
    const res = await fetch(`/api/file/${fileId}/meta`);
    const meta = await res.json();

    if (!res.ok) {
      badgeActive.style.display = 'none';
      badgeExpired.style.display = 'inline-flex';
      title.textContent = 'Link Unavailable';
      subtitle.textContent = meta.error || 'The file has expired or was removed.';
      document.getElementById('btnDecryptDownload').disabled = true;
      return;
    }

    activeReceiveFileMeta = meta;

    badgeActive.style.display = 'inline-flex';
    badgeExpired.style.display = 'none';
    title.textContent = 'Encrypted Payload Available';
    subtitle.textContent = 'Ciphertext is verified and ready for client-side decryption.';

    document.getElementById('receiveFileSize').textContent = formatBytes(meta.fileSize);

    // Downloads remaining
    if (meta.maxDownloads) {
      const left = Math.max(0, meta.maxDownloads - meta.downloadCount);
      document.getElementById('receiveDownloadsLeft').textContent = `${left} of ${meta.maxDownloads}`;
    } else {
      document.getElementById('receiveDownloadsLeft').textContent = 'Unlimited';
    }

    // Expiry time
    if (meta.expiresAt) {
      const remainingSecs = Math.max(0, Math.round((meta.expiresAt - Date.now()) / 1000));
      document.getElementById('receiveTimeLeft').textContent = formatTimeRemaining(remainingSecs);
    } else {
      document.getElementById('receiveTimeLeft').textContent = 'No expiry limit';
    }

    // Check if password required
    if (meta.hasPassword) {
      passphraseBlock.style.display = 'block';
    } else {
      passphraseBlock.style.display = 'none';
    }

    // Try decrypting metadata using URL key if available
    if (key && !meta.hasPassword) {
      try {
        const decryptedMeta = await window.CryptoEngine.decryptMeta(meta.encryptedMeta, key);
        document.getElementById('receiveFileName').textContent = decryptedMeta.name;
      } catch (err) {
        document.getElementById('receiveFileName').textContent = 'Protected (Key required)';
      }
    } else if (meta.hasPassword) {
      document.getElementById('receiveFileName').textContent = 'Protected by Passphrase';
    }

    document.getElementById('btnDecryptDownload').disabled = false;
  } catch (err) {
    console.error('Meta load failed:', err);
    errorBox.textContent = 'Could not load file details: ' + err.message;
    errorBox.style.display = 'block';
  }
}

function formatTimeRemaining(seconds) {
  if (seconds <= 0) return 'Expired';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

// Decrypt & Download Payload
async function handleDownloadAndDecrypt() {
  if (!activeReceiveFileId) {
    alert('No active file selected');
    return;
  }

  const btn = document.getElementById('btnDecryptDownload');
  const progressBox = document.getElementById('receiveProgressBox');
  const progressStatus = document.getElementById('receiveProgressStatus');
  const progressFill = document.getElementById('receiveProgressBarFill');
  const progressPercent = document.getElementById('receiveProgressPercent');
  const errorBox = document.getElementById('receiveErrorMessage');

  errorBox.style.display = 'none';
  btn.disabled = true;
  progressBox.style.display = 'block';
  progressFill.style.width = '20%';
  progressPercent.textContent = '20%';
  progressStatus.textContent = 'Downloading raw ciphertext blob...';

  try {
    const passphrase = document.getElementById('receivePassphraseInput').value;

    // 1. Download the encrypted payload
    const res = await fetch(`/api/file/${activeReceiveFileId}/download`);
    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.error || 'Ciphertext download rejected by server');
    }

    progressFill.style.width = '60%';
    progressPercent.textContent = '60%';
    progressStatus.textContent = 'Reading ciphertext stream...';

    const encryptedArrayBuffer = await res.arrayBuffer();

    progressFill.style.width = '80%';
    progressPercent.textContent = '80%';
    progressStatus.textContent = 'Decrypting AES-256-GCM in browser Web Crypto API...';

    // 2. Decrypt Metadata and File Payload
    let decryptedMeta;
    try {
      decryptedMeta = await window.CryptoEngine.decryptMeta(
        activeReceiveFileMeta.encryptedMeta,
        activeReceiveKey,
        passphrase,
        activeReceiveFileMeta.passwordSalt
      );
    } catch (e) {
      await reportCryptoResult(activeReceiveFileId, false, 'Invalid passphrase or key for metadata');
      throw new Error('Decryption failed! Incorrect passphrase or invalid key hash.');
    }

    let decryptedBuffer;
    try {
      decryptedBuffer = await window.CryptoEngine.decryptFile(
        encryptedArrayBuffer,
        activeReceiveKey,
        passphrase,
        activeReceiveFileMeta.passwordSalt
      );
    } catch (e) {
      await reportCryptoResult(activeReceiveFileId, false, 'Failed file ciphertext decryption');
      throw new Error('Ciphertext integrity check failed or bad key.');
    }

    // Report success to server audit log
    await reportCryptoResult(activeReceiveFileId, true);

    progressFill.style.width = '100%';
    progressPercent.textContent = '100%';
    progressStatus.textContent = 'Decryption successful! Saving file...';

    // 3. Trigger browser download of cleartext file
    const fileBlob = new Blob([decryptedBuffer], { type: decryptedMeta.type || 'application/octet-stream' });
    const downloadUrl = URL.createObjectURL(fileBlob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = decryptedMeta.name || `decrypted_${activeReceiveFileId}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(downloadUrl);

    showToast('File successfully decrypted and saved!', '🎉');

    // Update remaining downloads in UI
    setTimeout(() => {
      loadReceiveFile(activeReceiveFileId, activeReceiveKey);
    }, 1200);

  } catch (err) {
    console.error('Download/decryption error:', err);
    errorBox.textContent = err.message;
    errorBox.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
}

async function reportCryptoResult(fileId, success, errorReason = '') {
  try {
    await fetch(`/api/file/${fileId}/report-crypto`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ success, errorReason })
    });
  } catch (e) {
    // Non-blocking
  }
}

function loadManualLink() {
  const input = document.getElementById('manualLinkInput').value.trim();
  if (!input) return;

  if (input.includes('#')) {
    const hashPart = input.split('#')[1];
    const params = new URLSearchParams(hashPart);
    activeReceiveFileId = params.get('file');
    activeReceiveKey = params.get('key');
  } else {
    activeReceiveFileId = input;
  }

  if (activeReceiveFileId) {
    loadReceiveFile(activeReceiveFileId, activeReceiveKey);
  }
}

// -------------------------------------------------------------
// AUDIT LOGS & DASHBOARD
// -------------------------------------------------------------

async function fetchAuditStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    document.getElementById('statTotalFiles').textContent = data.totalFiles;
    document.getElementById('statActiveFiles').textContent = data.activeFiles;
    document.getElementById('statDownloads').textContent = data.totalDownloads;
    document.getElementById('statAuditEvents').textContent = data.totalAuditEvents;
  } catch (e) {
    console.error('Failed to load stats:', e);
  }
}

let cachedAuditLogs = [];

async function fetchAuditLogs(fileId = '') {
  const tbody = document.getElementById('auditTableBody');
  const filterType = document.getElementById('auditEventFilter').value;

  try {
    let url = `/api/audit-logs?limit=100`;
    if (fileId) url += `&fileId=${encodeURIComponent(fileId)}`;
    if (filterType) url += `&eventType=${encodeURIComponent(filterType)}`;

    const res = await fetch(url);
    const data = await res.json();
    cachedAuditLogs = data.logs || [];

    if (cachedAuditLogs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">No audit events recorded yet.</td></tr>';
      return;
    }

    tbody.innerHTML = cachedAuditLogs.map(log => {
      const timeStr = new Date(log.created_at).toLocaleString();
      const badgeClass = getBadgeClass(log.event_type);
      let detailsParsed = '';
      try {
        const d = JSON.parse(log.details);
        detailsParsed = Object.entries(d).map(([k, v]) => `<span style="color:var(--text-dim);">${k}:</span> <b>${v}</b>`).join(' | ');
      } catch (e) {
        detailsParsed = log.details || '-';
      }

      return `
        <tr>
          <td style="white-space: nowrap; font-family: monospace; font-size: 0.8rem; color: var(--text-muted);">${timeStr}</td>
          <td><span class="event-badge ${badgeClass}">${log.event_type}</span></td>
          <td style="font-family: monospace; font-size: 0.8rem; color: var(--accent-cyan);">${log.file_id ? log.file_id.substring(0, 8) + '...' : 'System'}</td>
          <td style="font-family: monospace; font-size: 0.8rem;">${log.client_ip || 'Unknown'}</td>
          <td style="font-size: 0.825rem;">${detailsParsed}</td>
        </tr>
      `;
    }).join('');

  } catch (e) {
    console.error('Audit fetch error:', e);
    tbody.innerHTML = `<tr><td colspan="5" style="color: var(--accent-rose); text-align: center; padding: 1.5rem;">Failed to load audit logs: ${e.message}</td></tr>`;
  }
}

function getBadgeClass(eventType) {
  if (eventType.includes('UPLOAD')) return 'badge-upload';
  if (eventType.includes('DOWNLOAD')) return 'badge-download';
  if (eventType.includes('EXPIRED') || eventType.includes('PURGED')) return 'badge-expired';
  if (eventType.includes('DELETED') || eventType.includes('REVOKED')) return 'badge-deleted';
  if (eventType.includes('CRYPTO') || eventType.includes('DECRYPTION')) return 'badge-crypto';
  return 'badge-inspect';
}

function exportAuditCsv() {
  if (!cachedAuditLogs || cachedAuditLogs.length === 0) {
    alert('No audit logs available to export');
    return;
  }

  const headers = ['ID', 'Timestamp', 'Date UTC', 'Event Type', 'File ID', 'Client IP', 'User Agent', 'Details'];
  const rows = cachedAuditLogs.map(log => [
    log.id,
    log.created_at,
    new Date(log.created_at).toISOString(),
    `"${log.event_type}"`,
    `"${log.file_id || ''}"`,
    `"${log.client_ip || ''}"`,
    `"${(log.user_agent || '').replace(/"/g, '""')}"`,
    `"${(log.details || '').replace(/"/g, '""')}"`
  ]);

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `audit_logs_${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('Audit trail exported as CSV', '📊');
}

// Check URL hash on page load
window.addEventListener('DOMContentLoaded', () => {
  inspectUrlParameters();
  window.addEventListener('hashchange', inspectUrlParameters);
});
