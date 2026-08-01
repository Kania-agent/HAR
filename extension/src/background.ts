import { Bridge } from './bridge.js';
import { DebuggerCapture } from './debugger.js';
import {
  clearRecentHosts,
  getAllowlist,
  getCaptureEnabled,
  getCaptureScope,
  getRecentHosts,
  getStickyTabs,
  getToken,
  recordHost,
  setAllowlist,
  setCaptureEnabled,
  setCaptureScope,
  setStickyTabs,
  setToken,
} from './store.js';
import { hostMatchesAllowlist, pushBounded, MAX_WS_MESSAGES, MAX_SSE_MESSAGES } from '@har-suite/shared';
import type {
  CaptureScope,
  CapturedRequest,
  WebSocketMessage,
  EventSourceMessage,
  PageEvent,
  ConsoleMessage,
  WebVitalMetrics,
  CaptchaDetection,
  CaptchaType,
} from '@har-suite/shared';
import { detectFromUrl, stableId } from './captcha-detector.js';

const KEEP_ALIVE_ALARM = 'bridge-keepalive';

const bridge = new Bridge(async () => await getToken());

const recentRequests = new Map<string, CapturedRequest>();
const RECENT_LIMIT = 500;

// Per-tab top-level URL, used to enrich captcha detections with the page that triggered them.
const tabPageUrl = new Map<number, string>();
// Tracks which tabs have already had the content-captcha scanner injected
// (per top-level URL). Prevents stacking page-world hooks on SPA navigations.
const injectedScanner = new Map<number, string>();
// Local dedupe for captcha detections so we don't spam the bridge with the same hit.
const seenCaptchas = new Map<string, number>();
const SEEN_CAPTCHA_LIMIT = 500;
const CAPTCHA_DEDUPE_MS = 30_000;

// Tabs that should keep capturing across same-tab navigations to ANY host (flow
// capture). A tab becomes sticky when it matches the allowlist while capture is on,
// or when the user clicks "Capture this tab". Persisted to storage.session so an SW
// eviction mid-flow doesn't drop it.
const stickyTabs = new Set<number>();

// Cached capture scope, kept in sync with storage. Read synchronously by the
// debugger's hot path via getScope().
let currentScope: CaptureScope = 'data';

async function persistSticky() {
  await setStickyTabs(Array.from(stickyTabs));
}

function emitCaptcha(detection: CaptchaDetection) {
  const now = Date.now();
  const last = seenCaptchas.get(detection.id) ?? 0;
  if (now - last < CAPTCHA_DEDUPE_MS) return;
  seenCaptchas.set(detection.id, now);
  // Bounded LRU: drop oldest insertion when over the limit.
  if (seenCaptchas.size > SEEN_CAPTCHA_LIMIT) {
    const oldestKey = seenCaptchas.keys().next().value;
    if (oldestKey) seenCaptchas.delete(oldestKey);
  }
  bridge.send({ kind: 'captcha-detected', payload: detection });
}

function maybeDetectCaptcha(req: CapturedRequest) {
  const pageUrl = tabPageUrl.get(req.tabId) ?? '';
  const pageHost = pageUrl
    ? (() => {
        try {
          return new URL(pageUrl).host;
        } catch {
          return '';
        }
      })()
    : '';
  const det = detectFromUrl({
    url: req.url,
    pageUrl,
    pageHost: pageHost || req.host,
    requestId: req.id,
    tabId: req.tabId,
    requestBody: req.requestBody,
  });
  if (det) emitCaptcha(det);
}

/** Detect captchas from raw URLs (including Script/Document types not captured by HAR). */
function maybeDetectCaptchaFromUrl(
  url: string,
  tabId: number,
  requestId: string,
  requestBody?: string,
) {
  const pageUrl = tabPageUrl.get(tabId) ?? '';
  const pageHost = pageUrl
    ? (() => {
        try {
          return new URL(pageUrl).host;
        } catch {
          return '';
        }
      })()
    : '';
  const det = detectFromUrl({
    url,
    pageUrl,
    pageHost,
    requestId,
    tabId,
    requestBody,
  });
  if (det) emitCaptcha(det);
}

const capture = new DebuggerCapture(
  {
    onRequest: (req) => {
      recentRequests.set(req.id, req);
      if (recentRequests.size > RECENT_LIMIT) {
        const firstKey = recentRequests.keys().next().value;
        if (firstKey) recentRequests.delete(firstKey);
      }
      bridge.send({ kind: 'request', payload: req });
      maybeDetectCaptcha(req);
    },
    onUpdate: (id, patch) => {
      const cur = recentRequests.get(id);
      if (cur) Object.assign(cur, patch);
      bridge.send({ kind: 'request-update', id, patch });
    },
    onWsMessage: (id, message: WebSocketMessage) => {
      const cur = recentRequests.get(id);
      if (cur) {
        cur.wsMessages = cur.wsMessages ?? [];
        pushBounded(cur.wsMessages, message, MAX_WS_MESSAGES);
      }
      bridge.send({ kind: 'ws-message', id, message });
    },
    onSseMessage: (id, message: EventSourceMessage) => {
      const cur = recentRequests.get(id);
      if (cur) {
        cur.eventSourceMessages = cur.eventSourceMessages ?? [];
        pushBounded(cur.eventSourceMessages, message, MAX_SSE_MESSAGES);
      }
      bridge.send({ kind: 'sse-message', id, message });
    },
    onPageEvent: (tabId: number, event: PageEvent) => {
      bridge.send({ kind: 'page-event', tabId, event });
    },
    onConsoleMessage: (tabId: number, message: ConsoleMessage) => {
      bridge.send({ kind: 'console-message', tabId, message });
    },
    onMetrics: (tabId: number, metrics: WebVitalMetrics) => {
      bridge.send({ kind: 'metrics', tabId, metrics });
    },
    onCaptchaUrl: (url, tabId, requestId, requestBody) => {
      // Runs for ALL request types including Script/Document that HAR capture
      // filters out — ensures captcha script loads and iframe loads are detected.
      maybeDetectCaptchaFromUrl(url, tabId, requestId, requestBody);
    },
  },
  () => currentScope,
);

function parseHost(url: string | undefined): string {
  if (!url) return '';
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
}

async function syncTabsWithAllowlist() {
  const enabled = await getCaptureEnabled();
  const allowlist = await getAllowlist();
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    if (tab.id == null || !tab.url) continue;
    const host = parseHost(tab.url);
    const matches = enabled && allowlist.length > 0 && hostMatchesAllowlist(host, allowlist);
    if (matches) {
      if (!stickyTabs.has(tab.id)) {
        stickyTabs.add(tab.id);
      }
      if (!capture.isAttached(tab.id)) {
        await capture.attach(tab.id);
        await injectCaptchaScanner(tab.id, tab.url);
      }
    } else if (enabled && stickyTabs.has(tab.id)) {
      // Keep a sticky tab attached even though its current host isn't allowlisted —
      // this is the flow-capture case (chatgpt.com → stripe.com in the same tab).
      if (!capture.isAttached(tab.id)) await capture.attach(tab.id);
    } else if (capture.isAttached(tab.id)) {
      await capture.detach(tab.id);
      stickyTabs.delete(tab.id);
    }
  }
  await persistSticky();
}

async function maybeAttachTab(tabId: number, url: string | undefined) {
  if (!url) return;
  // Always track per-tab page URL so captcha detection knows where we are.
  tabPageUrl.set(tabId, url);

  const host = parseHost(url);
  // Record the host for the "Recent" list BEFORE the capture-enabled check, so
  // sites show up even when capture is currently disabled.
  if (host) await recordHost(host);

  const enabled = await getCaptureEnabled();
  if (!enabled) {
    if (capture.isAttached(tabId)) await capture.detach(tabId);
    if (stickyTabs.delete(tabId)) await persistSticky();
    injectedScanner.delete(tabId);
    return;
  }

  const allowlist = await getAllowlist();
  const matches = host && hostMatchesAllowlist(host, allowlist);

  if (matches) {
    // Allowlist match makes the tab sticky so it keeps capturing if the flow leaves
    // the allowlisted host later in the same tab.
    if (!stickyTabs.has(tabId)) {
      stickyTabs.add(tabId);
      await persistSticky();
    }
    await capture.attach(tabId);
    await injectCaptchaScanner(tabId, url);
  } else if (stickyTabs.has(tabId)) {
    // Same-tab navigation to a non-allowlisted flow host — keep capturing and
    // inject the scanner on the new host so captcha detection works there too.
    await capture.attach(tabId);
    await injectCaptchaScanner(tabId, url);
  } else {
    if (capture.isAttached(tabId)) await capture.detach(tabId);
    injectedScanner.delete(tabId);
  }
}

/** Mark a tab sticky and attach immediately (manual "Capture this tab"). */
async function captureTab(tabId: number) {
  stickyTabs.add(tabId);
  await persistSticky();
  await capture.attach(tabId);
  const url = tabPageUrl.get(tabId);
  if (url) await injectCaptchaScanner(tabId, url);
}

/** Stop sticky capture for a tab; detach unless its host is independently allowlisted. */
async function uncaptureTab(tabId: number) {
  stickyTabs.delete(tabId);
  await persistSticky();
  const url = tabPageUrl.get(tabId);
  const host = parseHost(url);
  const allowlist = await getAllowlist();
  if (!(host && hostMatchesAllowlist(host, allowlist))) {
    await capture.detach(tabId);
    injectedScanner.delete(tabId);
  }
}

async function disableCapture() {
  await capture.detachAll();
  stickyTabs.clear();
  injectedScanner.clear();
  await persistSticky();
}

async function injectCaptchaScanner(tabId: number, url: string) {
  // Only inject once per (tabId, top-level URL) — re-injection stacks page-world hooks.
  const last = injectedScanner.get(tabId);
  if (last === url) return;
  try {
    await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      files: ['content-captcha.js'],
    });
    injectedScanner.set(tabId, url);
  } catch {
    // chrome://, about:, file:// etc. reject injection — that's fine.
  }
}

async function broadcastStatus() {
  bridge.send({
    kind: 'status',
    capturing: await getCaptureEnabled(),
    allowlist: await getAllowlist(),
    scope: currentScope,
    attachedTabs: capture.attachedCount(),
  });
}

// Restore cached scope + sticky tabs as early as possible (also after SW restart).
async function hydrateState() {
  currentScope = await getCaptureScope();
  const sticky = await getStickyTabs();
  for (const id of sticky) stickyTabs.add(id);
}

// Keep-alive: poke the worker just under the typical SW idle window.
// Chrome enforces a minimum of 0.5 min in production for non-dev extensions.
chrome.alarms.create(KEEP_ALIVE_ALARM, { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== KEEP_ALIVE_ALARM) return;
  // Touching state keeps the worker warm.
  await getCaptureEnabled();
  if (!bridge.isOpen()) bridge.forceReconnect();
});

chrome.runtime.onInstalled.addListener(async () => {
  await hydrateState();
  bridge.start();
  syncTabsWithAllowlist();
});
chrome.runtime.onStartup.addListener(async () => {
  await hydrateState();
  bridge.start();
  syncTabsWithAllowlist();
});

// When the bridge authenticates with the desktop (initial connect or reconnect),
// push the extension's current state so both sides stay in sync without polling.
bridge.onAuthenticated(async () => {
  try {
    await broadcastStatus();
  } catch (e) {
    console.warn('[bridge] post-auth sync failed', e);
  }
});

// Hydrate on initial worker spin-up too (covers the common dev/run path where
// neither onInstalled nor onStartup fires before the first event).
hydrateState();
bridge.start();

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  await maybeAttachTab(details.tabId, details.url);
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  if (capture.isAttached(tabId)) capture.detach(tabId);
  tabPageUrl.delete(tabId);
  injectedScanner.delete(tabId);
  if (stickyTabs.delete(tabId)) await persistSticky();
});

chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status !== 'loading' || !tab.url) return;
  await maybeAttachTab(tabId, tab.url);
});

bridge.onMessage(async (msg) => {
  if (msg.kind === 'set-allowlist') {
    await setAllowlist(msg.domains);
    bridge.send({ kind: 'allowlist-sync', domains: await getAllowlist() });
    await syncTabsWithAllowlist();
  } else if (msg.kind === 'set-capture') {
    await setCaptureEnabled(msg.enabled);
    if (!msg.enabled) await disableCapture();
    else await syncTabsWithAllowlist();
    await broadcastStatus();
  } else if (msg.kind === 'set-capture-scope') {
    currentScope = msg.scope;
    await setCaptureScope(msg.scope);
    await broadcastStatus();
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg?.kind === 'popup-get-state') {
      const activeId = await resolveActiveTabId(msg.tabId);
      sendResponse({
        capturing: await getCaptureEnabled(),
        allowlist: await getAllowlist(),
        scope: currentScope,
        connected: bridge.isOpen(),
        attachedTabs: capture.attachedCount(),
        token: await getToken(),
        recentHosts: await getRecentHosts(),
        activeTabSticky: activeId != null && stickyTabs.has(activeId),
      });
    } else if (msg?.kind === 'popup-set-allowlist') {
      await setAllowlist(msg.domains ?? []);
      await syncTabsWithAllowlist();
      bridge.send({ kind: 'allowlist-sync', domains: await getAllowlist() });
      sendResponse({ ok: true });
    } else if (msg?.kind === 'popup-set-capture') {
      await setCaptureEnabled(!!msg.enabled);
      if (msg.enabled) await syncTabsWithAllowlist();
      else await disableCapture();
      sendResponse({ ok: true });
    } else if (msg?.kind === 'popup-set-scope') {
      currentScope = msg.scope === 'all' ? 'all' : 'data';
      await setCaptureScope(currentScope);
      await broadcastStatus();
      sendResponse({ ok: true });
    } else if (msg?.kind === 'popup-capture-tab') {
      const tid = await resolveActiveTabId(msg.tabId);
      if (tid != null) await captureTab(tid);
      sendResponse({ ok: tid != null });
    } else if (msg?.kind === 'popup-uncapture-tab') {
      const tid = await resolveActiveTabId(msg.tabId);
      if (tid != null) await uncaptureTab(tid);
      sendResponse({ ok: tid != null });
    } else if (msg?.kind === 'popup-set-token') {
      await setToken(String(msg.token ?? ''));
      bridge.forceReconnect();
      sendResponse({ ok: true });
    } else if (msg?.kind === 'popup-clear-recent') {
      await clearRecentHosts();
      sendResponse({ ok: true });
    } else if (msg?.kind === 'content-captcha-detected') {
      const tabId = _sender.tab?.id ?? -1;
      const pageUrl = _sender.tab?.url ?? msg.pageUrl ?? '';
      let pageHost = '';
      try {
        pageHost = pageUrl ? new URL(pageUrl).host : '';
      } catch {}
      const allowlist = await getAllowlist();
      // Accept if the page is allowlisted OR the sender tab is being captured
      // (sticky/attached) — so DOM/script captcha detection works on flow hosts.
      const allowed =
        (pageHost && hostMatchesAllowlist(pageHost, allowlist)) ||
        (tabId >= 0 && (stickyTabs.has(tabId) || capture.isAttached(tabId)));
      if (!allowed) {
        sendResponse({ ok: false, error: 'host-not-allowlisted' });
        return;
      }
      const type = msg.type as CaptchaType;
      const sitekey = String(msg.sitekey ?? '');
      emitCaptcha({
        id: stableId(type, sitekey, pageHost),
        type,
        sitekey,
        pageUrl,
        pageHost,
        sourceUrl: pageUrl,
        source: msg.source === 'script' ? 'script' : 'dom',
        detectedAt: Date.now(),
        tabId,
        extra: msg.extra,
      });
      sendResponse({ ok: true });
    } else {
      sendResponse({ ok: false, error: 'unknown' });
    }
  })();
  return true;
});

async function resolveActiveTabId(explicit?: number): Promise<number | null> {
  if (typeof explicit === 'number') return explicit;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id ?? null;
}
