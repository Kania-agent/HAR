import Database from 'better-sqlite3';
import { app } from 'electron';
import { join } from 'node:path';
import { mkdirSync } from 'node:fs';
import type { CapturedRequest, CaptchaDetection, Session } from '@har-suite/shared';

let db: Database.Database | null = null;

export function initDb(): Database.Database {
  if (db) return db;
  const dir = join(app.getPath('userData'), 'har-suite');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, 'capture.db');
  db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  // SQLite has foreign keys disabled by default — enable so ON DELETE CASCADE
  // on requests/captchas actually fires when a session is deleted.
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      createdAt INTEGER NOT NULL,
      closedAt INTEGER
    );
    CREATE TABLE IF NOT EXISTS requests (
      id TEXT NOT NULL,
      sessionId INTEGER NOT NULL,
      data TEXT NOT NULL,
      host TEXT,
      type TEXT,
      method TEXT,
      status INTEGER,
      startedAt INTEGER,
      remoteAddress TEXT,
      remotePort INTEGER,
      protocol TEXT,
      wsError TEXT,
      wsStatus INTEGER,
      PRIMARY KEY (sessionId, id),
      FOREIGN KEY (sessionId) REFERENCES sessions(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_requests_session ON requests(sessionId, startedAt);
    CREATE TABLE IF NOT EXISTS prefs (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS captchas (
      id TEXT NOT NULL,
      sessionId INTEGER NOT NULL,
      type TEXT NOT NULL,
      sitekey TEXT NOT NULL,
      pageUrl TEXT,
      pageHost TEXT,
      sourceUrl TEXT,
      source TEXT,
      detectedAt INTEGER NOT NULL,
      data TEXT NOT NULL,
      PRIMARY KEY (sessionId, id),
      FOREIGN KEY (sessionId) REFERENCES sessions(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_captchas_session ON captchas(sessionId, detectedAt);
  `);
  // Migrate existing databases: add new columns that may not exist yet.
  // Each ALTER is wrapped in try/catch because SQLite errors on duplicate columns.
  const newColumns: Array<[string, string]> = [
    ['remoteAddress', 'TEXT'],
    ['remotePort', 'INTEGER'],
    ['protocol', 'TEXT'],
    ['wsError', 'TEXT'],
    ['wsStatus', 'INTEGER'],
  ];
  for (const [col, type] of newColumns) {
    try {
      db.exec(`ALTER TABLE requests ADD COLUMN ${col} ${type}`);
    } catch {
      // Column already exists — expected on databases created after the schema update.
    }
  }
  return db;
}

export function closeDb() {
  try {
    db?.close();
  } catch {}
  db = null;
}

export function createSession(name?: string): number {
  const d = initDb();
  const createdAt = Date.now();
  const sessionName = name ?? new Date(createdAt).toISOString().replace(/[:.]/g, '-');
  const info = d
    .prepare('INSERT INTO sessions (name, createdAt) VALUES (?, ?)')
    .run(sessionName, createdAt);
  return Number(info.lastInsertRowid);
}

export function closeSession(sessionId: number): void {
  const d = initDb();
  d.prepare('UPDATE sessions SET closedAt = ? WHERE id = ?').run(Date.now(), sessionId);
}

export function listSessions(): Session[] {
  const d = initDb();
  return d
    .prepare(
      `
    SELECT s.id, s.name, s.createdAt, s.closedAt,
           (SELECT COUNT(*) FROM requests r WHERE r.sessionId = s.id) AS count
    FROM sessions s
    ORDER BY s.createdAt DESC
  `,
    )
    .all() as Session[];
}

export function deleteSession(sessionId: number): void {
  const d = initDb();
  const tx = d.transaction(() => {
    d.prepare('DELETE FROM requests WHERE sessionId = ?').run(sessionId);
    d.prepare('DELETE FROM captchas WHERE sessionId = ?').run(sessionId);
    d.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
  });
  tx();
}

export function renameSession(sessionId: number, name: string): void {
  const d = initDb();
  d.prepare('UPDATE sessions SET name = ? WHERE id = ?').run(name, sessionId);
}

export function saveRequest(sessionId: number, req: CapturedRequest): void {
  const d = initDb();
  d.prepare(
    `
    INSERT OR REPLACE INTO requests (id, sessionId, data, host, type, method, status, startedAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `,
  ).run(
    req.id,
    sessionId,
    JSON.stringify(req),
    req.host,
    req.type,
    req.method,
    req.status ?? null,
    req.startedAt,
  );
}

export function saveRequestsBatch(sessionId: number, reqs: CapturedRequest[]): void {
  const d = initDb();
  const stmt = d.prepare(`
    INSERT OR REPLACE INTO requests (id, sessionId, data, host, type, method, status, startedAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const tx = d.transaction((items: CapturedRequest[]) => {
    for (const req of items) {
      stmt.run(
        req.id,
        sessionId,
        JSON.stringify(req),
        req.host,
        req.type,
        req.method,
        req.status ?? null,
        req.startedAt,
      );
    }
  });
  tx(reqs);
}

export function loadRequests(sessionId: number): CapturedRequest[] {
  const d = initDb();
  const rows = d
    .prepare('SELECT data FROM requests WHERE sessionId = ? ORDER BY startedAt ASC')
    .all(sessionId) as { data: string }[];
  return rows.map((r) => JSON.parse(r.data) as CapturedRequest);
}

export function saveCaptcha(sessionId: number, det: CaptchaDetection): void {
  const d = initDb();
  d.prepare(
    `INSERT OR REPLACE INTO captchas
     (id, sessionId, type, sitekey, pageUrl, pageHost, sourceUrl, source, detectedAt, data)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    det.id,
    sessionId,
    det.type,
    det.sitekey,
    det.pageUrl,
    det.pageHost,
    det.sourceUrl,
    det.source,
    det.detectedAt,
    JSON.stringify(det),
  );
}

export function loadCaptchas(sessionId: number): CaptchaDetection[] {
  const d = initDb();
  const rows = d
    .prepare('SELECT data FROM captchas WHERE sessionId = ? ORDER BY detectedAt ASC')
    .all(sessionId) as { data: string }[];
  return rows.map((r) => JSON.parse(r.data) as CaptchaDetection);
}

export function clearCaptchas(sessionId: number): void {
  const d = initDb();
  d.prepare('DELETE FROM captchas WHERE sessionId = ?').run(sessionId);
}

export function clearRequests(sessionId: number): void {
  const d = initDb();
  d.prepare('DELETE FROM requests WHERE sessionId = ?').run(sessionId);
}

/**
 * Delete sessions that have no requests and no captchas. Used on startup to
 * tidy up after dev iterations where Ctrl+C left empty session rows behind.
 * Optionally keep one specific session (e.g. the newly-created one for this run).
 */
export function purgeEmptySessions(keepId?: number): number {
  const d = initDb();
  const params = keepId != null ? [keepId] : [];
  const whereKeep = keepId != null ? 'AND id != ?' : '';
  const info = d
    .prepare(
      `DELETE FROM sessions
       WHERE id NOT IN (SELECT DISTINCT sessionId FROM requests)
         AND id NOT IN (SELECT DISTINCT sessionId FROM captchas)
         ${whereKeep}`,
    )
    .run(...params);
  return info.changes;
}

export function setPref(key: string, value: unknown): void {
  const d = initDb();
  d.prepare('INSERT OR REPLACE INTO prefs (key, value) VALUES (?, ?)').run(
    key,
    JSON.stringify(value),
  );
}

export function getPref<T>(key: string, fallback: T): T {
  const d = initDb();
  const row = d.prepare('SELECT value FROM prefs WHERE key = ?').get(key) as
    | { value: string }
    | undefined;
  if (!row) return fallback;
  try {
    return JSON.parse(row.value) as T;
  } catch {
    return fallback;
  }
}
