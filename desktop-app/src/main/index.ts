import { app, BrowserWindow, ipcMain, dialog, clipboard } from 'electron';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { BridgeServer } from './bridge-server';
import { exportHar, exportZip } from './export';
import { toCurl, toFetch } from './curl';
import { redactRequest } from './redact';
import { importHarFile } from './import';
import { MitmCapture, type CaptureSink } from './proxy/mitm-capture';
import { getRunningProcesses } from './proxy/process-resolver';
import { ensureCa, installCa, isCaInstalled, ensureCaBundle, caCertPath } from './proxy/ca-trust';
import {
  enableProxy,
  restoreProxy,
  restoreProxySync,
  type ProxySnapshot,
} from './proxy/system-proxy';
import { buildCaptureEnv, envPreview } from './proxy/capture-env';
import { CommandRunner, type CommandOutput } from './proxy/command-runner';
import {
  enableGlobalEnv,
  restoreGlobalEnv,
  restoreGlobalEnvSync,
  type EnvSnapshot,
} from './proxy/global-env';
import {
  clearCaptchas,
  clearRequests,
  closeDb,
  closeSession,
  createSession,
  deleteSession,
  getPref,
  initDb,
  listSessions,
  loadCaptchas,
  loadRequests,
  purgeEmptySessions,
  renameSession,
  saveCaptcha,
  saveRequest,
  saveRequestsBatch,
  setPref,
} from './store';
import type {
  CapturedRequest,
  BridgeMessage,
  WebSocketMessage,
  EventSourceMessage,
  PageEvent,
  RedactionConfig,
  CaptchaDetection,
  CaptureScope,
} from '@har-suite/shared';
import { DEFAULT_REDACTION } from '@har-suite/shared';

let mainWindow: BrowserWindow | null = null;
const bridge = new BridgeServer();

const requests = new Map<string, CapturedRequest>();
const captchas = new Map<string, CaptchaDetection>();
let allowlist: string[] = [];
let captureEnabled = true;
let captureScope: CaptureScope = 'data';
let currentSessionId: number | null = null;
let bridgeToken = '';
let redaction: RedactionConfig = DEFAULT_REDACTION;

// ── Native-app (MITM proxy) capture state ──
const APP_PROXY_PORT = 8888;
const PROXY_URL = `http://127.0.0.1:${APP_PROXY_PORT}`;
let mitm: MitmCapture | null = null;
let proxyRunning = false;
let appCaptureEnabled = false;
// Saved Windows proxy settings to restore on disable/exit. Also persisted to
// prefs so a crash mid-capture can still be cleaned up on next launch.
let savedProxy: ProxySnapshot | null = null;

// ── CLI / dev-tool capture state ──
const commandRunner = new CommandRunner();
let globalEnvActive = false;
// Saved HKCU\Environment values to restore when global CLI capture is turned
// off / on exit / after a crash.
let savedUserEnv: EnvSnapshot | null = null;

// ── Per-app capture filter ──
// List of allowed .exe names (e.g., ["node.exe", "claude.exe"])
let appFilter: string[] = [];
// Bypass flag: when true, capture all apps regardless of filter
let appFilterBypass = false;

// Persistence strategy:
//   - New requests are written IMMEDIATELY (single INSERT) so a crash/Ctrl+C
//     doesn't lose the row.
//   - Subsequent updates (response body, ws frames, timing) are batched per
//     request id and flushed every 250ms.
const pendingUpdates = new Map<string, CapturedRequest>();
let flushTimer: ReturnType<typeof setTimeout> | null = null;
const FLUSH_INTERVAL_MS = 250;

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(flushNow, FLUSH_INTERVAL_MS);
}

function flushNow() {
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
  if (pendingUpdates.size === 0 || currentSessionId == null) return;
  const items = Array.from(pendingUpdates.values());
  pendingUpdates.clear();
  try {
    saveRequestsBatch(currentSessionId, items);
  } catch (e) {
    console.warn('[store] batch save failed', e);
  }
}

function persistUpdate(req: CapturedRequest) {
  if (currentSessionId == null) return;
  pendingUpdates.set(req.id, req);
  scheduleFlush();
}

function sendToRenderer(channel: string, payload: unknown) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

function applyRequest(req: CapturedRequest) {
  requests.set(req.id, req);
  // INSERT immediately so the row exists even if the app dies before any
  // batched update fires.
  if (currentSessionId != null) {
    try {
      saveRequest(currentSessionId, req);
    } catch (e) {
      console.warn('[store] saveRequest failed', e);
    }
  }
  sendToRenderer('capture:request', req);
}

function applyUpdate(id: string, patch: Partial<CapturedRequest>) {
  const cur = requests.get(id);
  if (cur) {
    Object.assign(cur, patch);
    persistUpdate(cur);
    sendToRenderer('capture:update', { id, patch });
  }
}

function applyWsMessage(id: string, msg: WebSocketMessage) {
  const cur = requests.get(id);
  if (cur) {
    cur.wsMessages = cur.wsMessages ?? [];
    cur.wsMessages.push(msg);
    persistUpdate(cur);
    sendToRenderer('capture:ws-message', { id, message: msg });
  }
}

function applySseMessage(id: string, msg: EventSourceMessage) {
  const cur = requests.get(id);
  if (cur) {
    cur.eventSourceMessages = cur.eventSourceMessages ?? [];
    cur.eventSourceMessages.push(msg);
    persistUpdate(cur);
    sendToRenderer('capture:sse-message', { id, message: msg });
  }
}

function applyPageEvent(tabId: number, event: PageEvent) {
  // Page events are not tied to a single request; broadcast to renderer for
  // timeline display. They are not persisted per-request but could be added
  // to a dedicated page_events table in the future.
  sendToRenderer('capture:page-event', { tabId, event });
}

// Single ingestion surface shared by BOTH capture sources (the Chrome-extension
// bridge and the native-app MITM proxy). App rows therefore get the same
// immediate-INSERT + batched-update + renderer push as web rows.
const sink: CaptureSink = {
  onRequest: applyRequest,
  onUpdate: applyUpdate,
  onWsMessage: applyWsMessage,
  onCaptchaDetected: applyCaptcha,
};
mitm = new MitmCapture(
  sink,
  () => captureScope,
  () => ({
    allowlist: appFilter,
    bypass: appFilterBypass,
  }),
  () => captureEnabled,
);

function applyCaptcha(det: CaptchaDetection) {
  const existing = captchas.get(det.id);
  // Prefer the entry with a non-empty sitekey or the more specific source.
  if (existing && existing.sitekey && !det.sitekey) return;
  captchas.set(det.id, det);
  if (currentSessionId != null) {
    try {
      saveCaptcha(currentSessionId, det);
    } catch (e) {
      console.warn('[store] saveCaptcha failed', e);
    }
  }
  sendToRenderer('capture:captcha', det);
}

bridge.on('message', (msg: BridgeMessage) => {
  switch (msg.kind) {
    case 'request':
      applyRequest(msg.payload);
      break;
    case 'request-update':
      applyUpdate(msg.id, msg.patch);
      break;
    case 'ws-message':
      applyWsMessage(msg.id, msg.message);
      break;
    case 'sse-message':
      applySseMessage(msg.id, msg.message);
      break;
    case 'page-event':
      applyPageEvent(msg.tabId, msg.event);
      break;
    case 'status':
      allowlist = msg.allowlist;
      captureEnabled = msg.capturing;
      // `scope` is optional on the wire (older extensions omit it) — default 'data'.
      if (msg.scope) captureScope = msg.scope;
      sendToRenderer('capture:status', {
        allowlist,
        captureEnabled,
        scope: captureScope,
        connected: true,
      });
      break;
    case 'allowlist-sync':
      allowlist = msg.domains;
      sendToRenderer('capture:status', { allowlist, captureEnabled, connected: true });
      break;
    case 'captcha-detected':
      applyCaptcha(msg.payload);
      break;
  }
});

bridge.on('connected', () => sendToRenderer('capture:connection', { connected: true }));
bridge.on('disconnected', () =>
  sendToRenderer('capture:connection', { connected: bridge.hasClient() }),
);

function generateToken(): string {
  return randomBytes(16).toString('hex');
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#1e1e1e',
    title: 'HAR Capture Suite',
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  if (process.env.ELECTRON_RENDERER_URL) {
    mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ────────────── IPC handlers ──────────────

ipcMain.handle('capture:get-all', () => Array.from(requests.values()));

ipcMain.handle('capture:clear', () => {
  requests.clear();
  pendingUpdates.clear(); // cleared BEFORE the DELETE so no pending batch flush
  captchas.clear(); //       can re-persist the rows we're about to delete
  if (currentSessionId != null) {
    try {
      clearRequests(currentSessionId); // NEW — delete active session's persisted requests
      clearCaptchas(currentSessionId);
    } catch {}
  }
  return true;
});

ipcMain.handle('captchas:get-all', () => Array.from(captchas.values()));
ipcMain.handle('captchas:clear', () => {
  captchas.clear();
  if (currentSessionId != null) {
    try {
      clearCaptchas(currentSessionId);
    } catch {}
  }
  return true;
});

ipcMain.handle('capture:get-status', () => ({
  allowlist,
  captureEnabled,
  scope: captureScope,
  connected: bridge.hasClient(),
  total: requests.size,
  token: bridgeToken,
  sessionId: currentSessionId,
  redaction,
  appFilter,
  appFilterBypass,
}));

ipcMain.handle('capture:set-allowlist', (_e, domains: string[]) => {
  allowlist = domains;
  bridge.send({ kind: 'set-allowlist', domains });
  setPref('allowlist', domains);
  return true;
});

ipcMain.handle('capture:set-capture', (_e, enabled: boolean) => {
  captureEnabled = enabled; // master state (preserved)
  bridge.send({ kind: 'set-capture', enabled }); // stop extension capture (3.8)
  sendToRenderer('capture:status', {
    // NEW — status immediately accurate without waiting for a bridge round-trip (3.6)
    allowlist,
    captureEnabled,
    scope: captureScope,
    connected: bridge.hasClient(),
  });
  return true;
});

ipcMain.handle('capture:set-scope', (_e, scope: CaptureScope) => {
  captureScope = scope === 'all' ? 'all' : 'data';
  bridge.send({ kind: 'set-capture-scope', scope: captureScope });
  setPref('captureScope', captureScope);
  return true;
});

function broadcastAppCaptureStatus(extra?: { caInstalled?: boolean }) {
  sendToRenderer('capture:app-status', {
    enabled: appCaptureEnabled,
    port: APP_PROXY_PORT,
    proxyActive: appCaptureEnabled,
    ...(extra ?? {}),
  });
}

/**
 * Ensure the shared MITM proxy is up and our CA is generated + trusted. Used by
 * ALL three capture modes (GUI apps, run-command, global env) so they share one
 * proxy instance and one CA install. Idempotent.
 */
async function ensureProxyRunning(): Promise<void> {
  if (proxyRunning) return;
  const ca = await ensureCa();
  await installCa();
  await ensureCaBundle();
  if (!mitm)
    mitm = new MitmCapture(
      sink,
      () => captureScope,
      () => ({
        allowlist: appFilter,
        bypass: appFilterBypass,
      }),
      () => captureEnabled,
    );
  await mitm.start(APP_PROXY_PORT, ca);
  proxyRunning = true;
}

/** Stop the proxy only when NOTHING still needs it (no app/CLI capture active). */
async function stopProxyIfIdle(): Promise<void> {
  if (appCaptureEnabled || globalEnvActive || commandRunner.isRunning()) return;
  try {
    await mitm?.stop();
  } catch {}
  proxyRunning = false;
}

async function enableAppCapture(): Promise<{ ok: boolean; error?: string }> {
  if (process.platform !== 'win32') {
    return { ok: false, error: 'App capture is only supported on Windows.' };
  }
  if (appCaptureEnabled) return { ok: true };
  try {
    await ensureProxyRunning();
    // Point the system proxy at us and remember the prior settings.
    savedProxy = await enableProxy(APP_PROXY_PORT);
    setPref('savedProxy', savedProxy);
    appCaptureEnabled = true;
    broadcastAppCaptureStatus({ caInstalled: true });
    return { ok: true };
  } catch (e: any) {
    // Roll back partial state on failure so we never leave the proxy hijacked.
    try {
      if (savedProxy) await restoreProxy(savedProxy);
    } catch {}
    appCaptureEnabled = false;
    savedProxy = null;
    setPref('savedProxy', null);
    await stopProxyIfIdle();
    broadcastAppCaptureStatus();
    return { ok: false, error: String(e?.message ?? e) };
  }
}

async function disableAppCapture(): Promise<void> {
  if (savedProxy) {
    try {
      await restoreProxy(savedProxy);
    } catch (e) {
      console.warn('[app-capture] restore proxy failed', e);
    }
    savedProxy = null;
    setPref('savedProxy', null);
  }
  appCaptureEnabled = false;
  await stopProxyIfIdle();
  broadcastAppCaptureStatus();
}

ipcMain.handle('capture:set-app-capture', async (_e, enabled: boolean) => {
  if (enabled) return enableAppCapture();
  await disableAppCapture();
  return { ok: true };
});

ipcMain.handle('capture:get-app-capture-status', async () => ({
  enabled: appCaptureEnabled,
  port: APP_PROXY_PORT,
  proxyActive: appCaptureEnabled,
  caInstalled: await isCaInstalled(),
  supported: process.platform === 'win32',
}));

// ── CLI / dev-tool capture ──

async function captureEnvMap(): Promise<Record<string, string>> {
  const caBundlePath = await ensureCaBundle();
  return buildCaptureEnv({ proxyUrl: PROXY_URL, caCertPath: caCertPath(), caBundlePath });
}

ipcMain.handle(
  'capture:run-command',
  async (_e, args: { command: string; cwd?: string }): Promise<{ ok: boolean; error?: string }> => {
    if (process.platform !== 'win32') {
      return { ok: false, error: 'CLI capture is only supported on Windows.' };
    }
    try {
      await ensureProxyRunning();
      const env = await captureEnvMap();
      const res = commandRunner.run(
        args.command,
        env,
        (out: CommandOutput) => {
          sendToRenderer('capture:command-output', out);
          if (out.stream === 'exit' || out.stream === 'error') void stopProxyIfIdle();
        },
        args.cwd,
      );
      if (!res.ok) await stopProxyIfIdle();
      return res;
    } catch (e: any) {
      await stopProxyIfIdle();
      return { ok: false, error: String(e?.message ?? e) };
    }
  },
);

ipcMain.handle('capture:cancel-command', async () => {
  commandRunner.cancel();
  await stopProxyIfIdle();
  return true;
});

function broadcastCliStatus() {
  sendToRenderer('capture:cli-status', {
    proxyRunning,
    globalEnvActive,
    commandRunning: commandRunner.isRunning(),
  });
}

async function enableGlobalCli(): Promise<{ ok: boolean; error?: string }> {
  if (process.platform !== 'win32') {
    return { ok: false, error: 'CLI capture is only supported on Windows.' };
  }
  if (globalEnvActive) return { ok: true };
  try {
    await ensureProxyRunning();
    const env = await captureEnvMap();
    savedUserEnv = await enableGlobalEnv(env);
    setPref('savedUserEnv', savedUserEnv);
    globalEnvActive = true;
    broadcastCliStatus();
    return { ok: true };
  } catch (e: any) {
    try {
      if (savedUserEnv) await restoreGlobalEnv(savedUserEnv);
    } catch {}
    savedUserEnv = null;
    setPref('savedUserEnv', null);
    globalEnvActive = false;
    await stopProxyIfIdle();
    broadcastCliStatus();
    return { ok: false, error: String(e?.message ?? e) };
  }
}

async function disableGlobalCli(): Promise<void> {
  if (savedUserEnv) {
    try {
      await restoreGlobalEnv(savedUserEnv);
    } catch (e) {
      console.warn('[global-env] restore failed', e);
    }
    savedUserEnv = null;
    setPref('savedUserEnv', null);
  }
  globalEnvActive = false;
  await stopProxyIfIdle();
  broadcastCliStatus();
}

ipcMain.handle('capture:set-global-env', async (_e, enabled: boolean) => {
  if (enabled) return enableGlobalCli();
  await disableGlobalCli();
  return { ok: true };
});

ipcMain.handle('capture:get-cli-status', async () => ({
  proxyRunning,
  globalEnvActive,
  commandRunning: commandRunner.isRunning(),
  supported: process.platform === 'win32',
  envPreview: envPreview(await captureEnvMap()),
}));

// ── App filter ──
ipcMain.handle('capture:get-app-filter', () => ({
  exeNames: appFilter,
  bypass: appFilterBypass,
  seenExes: mitm ? mitm.getSeenExes() : [],
  runningProcesses: getRunningProcesses(),
}));

ipcMain.handle('capture:set-app-filter', (_e, data: { exeNames: string[]; bypass: boolean }) => {
  appFilter = data.exeNames;
  appFilterBypass = data.bypass;
  setPref('appFilter', { exeNames: appFilter, bypass: appFilterBypass });

  // Broadcast filter change to renderer
  sendToRenderer('capture:app-filter-changed', {
    exeNames: appFilter,
    bypass: appFilterBypass,
  });

  return true;
});

ipcMain.handle('capture:set-redaction', (_e, cfg: RedactionConfig) => {
  redaction = cfg;
  setPref('redaction', cfg);
  return true;
});

ipcMain.handle('capture:regenerate-token', () => {
  bridgeToken = generateToken();
  bridge.setToken(bridgeToken);
  setPref('bridgeToken', bridgeToken);
  return bridgeToken;
});

ipcMain.handle('capture:export', async (_e, args: { format: 'har' | 'zip'; ids?: string[] }) => {
  const items = args.ids
    ? args.ids.map((id) => requests.get(id)).filter((r): r is CapturedRequest => !!r)
    : Array.from(requests.values());

  const defaultName = `capture-${new Date().toISOString().replace(/[:.]/g, '-')}.${args.format}`;
  const out = await dialog.showSaveDialog({
    title: `Export ${args.format.toUpperCase()}`,
    defaultPath: defaultName,
    filters:
      args.format === 'har'
        ? [{ name: 'HAR Archive', extensions: ['har'] }]
        : [{ name: 'ZIP Archive', extensions: ['zip'] }],
  });
  if (out.canceled || !out.filePath) return { ok: false, error: 'cancelled' };

  try {
    const count =
      args.format === 'har'
        ? await exportHar(items, out.filePath, redaction)
        : await exportZip(items, out.filePath, redaction);
    return { ok: true, path: out.filePath, count };
  } catch (e: any) {
    return { ok: false, error: String(e?.message ?? e) };
  }
});

ipcMain.handle('capture:import-har', async () => {
  const res = await dialog.showOpenDialog({
    title: 'Import HAR',
    properties: ['openFile'],
    filters: [{ name: 'HAR / JSON', extensions: ['har', 'json'] }],
  });
  if (res.canceled || !res.filePaths[0]) return { ok: false, error: 'cancelled' };
  try {
    const imported = await importHarFile(res.filePaths[0]);
    for (const r of imported) {
      // applyRequest handles in-memory + immediate DB INSERT + renderer push.
      applyRequest(r);
    }
    return { ok: true, count: imported.length };
  } catch (e: any) {
    return { ok: false, error: String(e?.message ?? e) };
  }
});

ipcMain.handle('capture:to-curl', (_e, id: string) => {
  const r = requests.get(id);
  if (!r) return null;
  const curl = toCurl(redactRequest(r, redaction)); // CHANGED — apply redaction before building cURL
  clipboard.writeText(curl);
  return curl;
});

ipcMain.handle('capture:to-fetch', (_e, id: string) => {
  const r = requests.get(id);
  if (!r) return null;
  const code = toFetch(redactRequest(r, redaction)); // CHANGED — apply redaction before building fetch
  clipboard.writeText(code);
  return code;
});

ipcMain.handle('capture:copy-url', (_e, id: string) => {
  const r = requests.get(id);
  if (!r) return null;
  clipboard.writeText(r.url);
  return r.url;
});

ipcMain.handle('captchas:copy-sitekey', (_e, id: string) => {
  const c = captchas.get(id);
  if (!c) return null;
  clipboard.writeText(c.sitekey);
  return c.sitekey;
});

// ── Sessions ──
ipcMain.handle('sessions:list', () => listSessions());
ipcMain.handle('sessions:current', () => currentSessionId);
ipcMain.handle('sessions:new', (_e, name?: string) => {
  flushNow();
  if (currentSessionId != null) closeSession(currentSessionId);
  currentSessionId = createSession(name);
  requests.clear();
  captchas.clear();
  sendToRenderer('capture:cleared', { sessionId: currentSessionId });
  return currentSessionId;
});
ipcMain.handle('sessions:open', (_e, id: number) => {
  flushNow();
  if (currentSessionId != null && currentSessionId !== id) closeSession(currentSessionId);
  currentSessionId = id;
  const loaded = loadRequests(id);
  const loadedCaptchas = loadCaptchas(id);
  requests.clear();
  captchas.clear();
  for (const r of loaded) requests.set(r.id, r);
  for (const c of loadedCaptchas) captchas.set(c.id, c);
  sendToRenderer('capture:reloaded', {
    sessionId: id,
    requests: loaded,
    captchas: loadedCaptchas,
  });
  return loaded.length;
});
ipcMain.handle('sessions:delete', (_e, id: number) => {
  if (currentSessionId === id) {
    flushNow();
    currentSessionId = null;
    requests.clear();
    captchas.clear();
    sendToRenderer('capture:cleared', { sessionId: null });
  }
  deleteSession(id);
  return true;
});
ipcMain.handle('sessions:rename', (_e, id: number, name: string) => {
  renameSession(id, name);
  return true;
});

// ────────────── Lifecycle ──────────────

app.whenReady().then(async () => {
  try {
    initDb();
    // Restore prefs
    bridgeToken = getPref<string>('bridgeToken', '') || generateToken();
    setPref('bridgeToken', bridgeToken);
    bridge.setToken(bridgeToken);

    allowlist = getPref<string[]>('allowlist', []);
    redaction = getPref<RedactionConfig>('redaction', DEFAULT_REDACTION);
    captureScope = getPref<CaptureScope>('captureScope', 'data');

    const savedAppFilter = getPref<{ exeNames: string[]; bypass: boolean }>('appFilter', {
      exeNames: [],
      bypass: false,
    });
    appFilter = savedAppFilter.exeNames;
    appFilterBypass = savedAppFilter.bypass;

    // If a previous run crashed while app-capture was on, the Windows proxy may
    // still point at our (now-dead) port. Restore the saved settings on startup.
    const leftoverProxy = getPref<ProxySnapshot | null>('savedProxy', null);
    if (leftoverProxy) {
      try {
        await restoreProxy(leftoverProxy);
      } catch (e) {
        console.warn('[app-capture] startup proxy restore failed', e);
      }
      setPref('savedProxy', null);
    }

    // Likewise, if a crash left global CLI capture on, the user's persistent
    // environment may still point at our dead proxy — restore it.
    const leftoverEnv = getPref<EnvSnapshot | null>('savedUserEnv', null);
    if (leftoverEnv) {
      try {
        await restoreGlobalEnv(leftoverEnv);
      } catch (e) {
        console.warn('[global-env] startup env restore failed', e);
      }
      setPref('savedUserEnv', null);
    }

    // SAFETY: Always clean up proxy-related environment variables on startup.
    // This prevents CLI tools from failing if HAR Capture crashed without cleanup.
    // Only clean if there's no active global env capture (to avoid disrupting active use).
    if (!globalEnvActive) {
      const varsToCheck = ['HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'NODE_EXTRA_CA_CERTS'];
      for (const v of varsToCheck) {
        const val = process.env[v];
        // If env var points to our proxy (127.0.0.1:8888), remove it
        if (val && val.includes('127.0.0.1:8888')) {
          try {
            const { execFileSync } = require('child_process');
            execFileSync('reg', ['delete', 'HKCU\\Environment', '/v', v, '/f'], { stdio: 'ignore' });
            delete process.env[v];
            console.log(`[startup] Cleaned up leftover env var: ${v}`);
          } catch {}
        }
      }
    }

    // Start a fresh session on startup.
    currentSessionId = createSession();

    // Drop empty sessions left over from previous runs (Ctrl+C, crashes).
    try {
      const purged = purgeEmptySessions(currentSessionId);
      if (purged > 0) console.log(`[store] purged ${purged} empty session(s)`);
    } catch (e) {
      console.warn('[store] purge failed', e);
    }

    await bridge.start();
    console.log(`[bridge] listening on 127.0.0.1:9876, token=${bridgeToken}`);
  } catch (e) {
    console.error('[bridge] failed to start', e);
    dialog.showErrorBox(
      'Startup error',
      `Could not initialize: ${(e as Error)?.message ?? e}\n\nIs another instance running?`,
    );
  }
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

function gracefulShutdown() {
  flushNow();
  if (currentSessionId != null) {
    try {
      closeSession(currentSessionId);
    } catch {}
  }
  // Never leave the user's Windows proxy pointing at our (about-to-die) port.
  if (savedProxy) {
    restoreProxySync(savedProxy);
    setPref('savedProxy', null);
    savedProxy = null;
  }
  // Same for the persistent user environment (global CLI capture).
  // Always clean up HAR Capture env vars on exit to prevent CLI tools from
  // failing with "connection refused" when HAR Capture is not running.
  if (savedUserEnv) {
    restoreGlobalEnvSync(savedUserEnv);
    setPref('savedUserEnv', null);
    savedUserEnv = null;
  } else if (globalEnvActive) {
    // Fallback: if savedUserEnv is somehow lost but globalEnvActive is true,
    // we need to clean up the proxy env vars we set.
    // Delete the common proxy-related env vars from user environment.
    try {
      const { execFileSync } = require('child_process');
      const vars = [
        'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
        'http_proxy', 'https_proxy', 'all_proxy',
        'NO_PROXY', 'no_proxy',
        'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE',
        'CURL_CA_BUNDLE', 'GIT_SSL_CAINFO', 'CARGO_HTTP_CAINFO',
        'DENO_CERT', 'AWS_CA_BUNDLE', 'NODE_USE_ENV_PROXY'
      ];
      for (const v of vars) {
        try {
          execFileSync('reg', ['delete', 'HKCU\\Environment', '/v', v, '/f'], { stdio: 'ignore' });
        } catch {}
      }
      console.log('[shutdown] Cleaned up leftover proxy env vars');
    } catch (e) {
      console.warn('[shutdown] Failed to clean up env vars', e);
    }
    // Broadcast WM_SETTINGCHANGE to notify other processes
    try {
      const { execFileSync } = require('child_process');
      // Use PowerShell to broadcast the change
      execFileSync('powershell', ['-Command', '[Environment]::SetEnvironmentVariable("HTTPS_PROXY", $null, "User")'], { stdio: 'ignore' });
    } catch {}
  }
  // Kill any command we launched so it doesn't outlive the app with a dead proxy.
  try {
    commandRunner.cancel();
  } catch {}
}

app.on('before-quit', gracefulShutdown);

app.on('window-all-closed', () => {
  gracefulShutdown();
  bridge.stop();
  closeDb();
  if (process.platform !== 'darwin') app.quit();
});

// Best-effort flush on SIGINT (Ctrl+C in dev).
process.on('SIGINT', () => {
  gracefulShutdown();
  try {
    closeDb();
  } catch {}
  process.exit(0);
});
process.on('SIGTERM', () => {
  gracefulShutdown();
  try {
    closeDb();
  } catch {}
  process.exit(0);
});
