const { db } = require('./db');

function logEvent(fileId, eventType, req, details = {}) {
  try {
    const clientIp = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || req.ip || 'Unknown').replace('::ffff:', '');
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const createdAt = Date.now();
    
    const stmt = db.prepare(`
      INSERT INTO audit_logs (file_id, event_type, client_ip, user_agent, details, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    stmt.run(
      fileId || null,
      eventType,
      clientIp,
      userAgent,
      typeof details === 'object' ? JSON.stringify(details) : String(details),
      createdAt
    );
  } catch (err) {
    console.error('Failed to log audit event:', err);
  }
}

function getAuditLogs({ fileId, limit = 100, eventType } = {}) {
  let query = 'SELECT * FROM audit_logs WHERE 1=1';
  const params = [];

  if (fileId) {
    query += ' AND file_id = ?';
    params.push(fileId);
  }
  if (eventType) {
    query += ' AND event_type = ?';
    params.push(eventType);
  }

  query += ' ORDER BY created_at DESC LIMIT ?';
  params.push(Math.min(limit, 500));

  const stmt = db.prepare(query);
  return stmt.all(...params);
}

module.exports = {
  logEvent,
  getAuditLogs
};
