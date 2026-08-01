import {
  cdpDuration,
  mapResourceTypeFull,
  pickEvictionKey,
  shouldCapture,
  type CaptureScope,
  type CapturedHeader,
  type CapturedRequest,
  type ConsoleMessage,
  type EventSourceMessage,
  type Initiator,
  type PageEvent,
  type RedirectHop,
  type ResourceTiming,
  type SecurityDetails,
  type ResourceType,
  type WebSocketMessage,
  type WebVitalMetrics,
} from '@har-suite/shared';

const DEBUGGER_PROTOCOL = '1.3';

// Pause freshly-attached OOPIF/worker targets until we've enabled Network on
// them — this guarantees we don't miss a child's earliest requests (the ones
// that often carry a reCAPTCHA sitekey). The trade-off is that the target stays
// frozen until we call Runtime.runIfWaitingForDebugger, so the resume MUST always
// fire (see the `finally` in onAttachedToTarget). If paused-iframe hangs are ever
// observed (e.g. under MV3 service-worker eviction), flip this to `false`.
const WAIT_FOR_DEBUGGER = true;

// Which child target types to auto-attach into. "iframe" here means out-of-process
// (cross-origin) iframes — same-process frames already flow on the parent session.
const CHILD_FILTER = [
  { type: 'iframe' },
  { type: 'worker' },
  { type: 'shared_worker' },
  { type: 'service_worker' },
];

// Cap on concurrently in-flight requests we track. 0 = unlimited (capture on
// personal machine). Set to a positive number for memory-constrained environments.
const INFLIGHT_LIMIT = 0;

type Listener = {
  onRequest: (req: CapturedRequest) => void;
  onUpdate: (id: string, patch: Partial<CapturedRequest>) => void;
  onWsMessage: (id: string, msg: WebSocketMessage) => void;
  /** Fires for every SSE message received on an EventSource connection. */
  onSseMessage?: (id: string, msg: EventSourceMessage) => void;
  /** Fires for page lifecycle events (navigation, DOMContentLoaded, load). */
  onPageEvent?: (tabId: number, event: PageEvent) => void;
  /** Fires for JS console messages (console.log/warn/error + exceptions). */
  onConsoleMessage?: (tabId: number, msg: ConsoleMessage) => void;
  /** Fires for Core Web Vitals metrics snapshot. */
  onMetrics?: (tabId: number, metrics: WebVitalMetrics) => void;
  /** Fires for every request URL regardless of resource type — used for captcha detection. */
  onCaptchaUrl?: (url: string, tabId: number, requestId: string, requestBody?: string) => void;
};

/** A flat-session target descriptor accepted by chrome.debugger.sendCommand (Chrome 125+). */
type SessionTarget = chrome.debugger.Debuggee & { sessionId?: string };

interface SessionInfo {
  sessionId: string;
  tabId: number;
  target: SessionTarget;
  targetType: string;
}

interface InFlight {
  /** Public, namespaced id (`${sessionId}:${requestId}`) so cross-session ids never collide. */
  id: string;
  /** Map key — same as `id`. */
  key: string;
  tabId: number;
  /** Exact session to address Network.getResponseBody to. */
  sessionTarget: SessionTarget;
  type: ResourceType;
  method: string;
  url: string;
  host: string;
  startedAt: number;
  /** CDP MonotonicTime (seconds) captured at request start; undefined until known (e.g. WS pre-handshake). */
  startMonotonicSec?: number;
  requestHeaders: CapturedHeader[];
  requestBody?: string;
  /** Full initiator object (type, url, line, stack trace). */
  initiator?: Initiator;
  /** True when Chrome sets hasPostData but body is not inline (needs getRequestPostData). */
  hasPostData?: boolean;
  /** Accumulated redirect hops before the final request. */
  redirects?: RedirectHop[];
}

function headersToList(headers: Record<string, string> | undefined): CapturedHeader[] {
  if (!headers) return [];
  return Object.entries(headers).map(([name, value]) => ({ name, value: String(value) }));
}

function parseHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
}

export class DebuggerCapture {
  private attachedTabs = new Set<number>();
  // Synchronous reservation set (Bug 2). A tab is added here BEFORE the
  // `await chrome.debugger.attach` so a concurrent redundant attach() on the same
  // navigation hits the guard and returns without touching live state. Released in
  // the owning attempt's `finally`. Mirrors the pure AttachRegistry `attaching` set.
  private attaching = new Set<number>();
  // sessionId -> child session info. Root sessions have no sessionId and are
  // represented by tabId only (not stored here).
  private sessions = new Map<string, SessionInfo>();
  // tabId -> set of child sessionIds, for O(1) teardown when a tab detaches.
  private tabSessions = new Map<number, Set<string>>();
  private inFlight = new Map<string, InFlight>();
  private listener: Listener;
  private getScope: () => CaptureScope;

  constructor(listener: Listener, getScope: () => CaptureScope) {
    this.listener = listener;
    this.getScope = getScope;
    chrome.debugger.onEvent.addListener(this.handleEvent);
    chrome.debugger.onDetach.addListener(this.handleDetach);
  }

  async attach(tabId: number): Promise<void> {
    // Synchronous guard: already attached OR a reservation is in flight → no-op.
    // A redundant concurrent attach (e.g. webNavigation.onCommitted frameId 0 AND
    // tabs.onUpdated 'loading' on one navigation) returns here without touching
    // live state, so its would-be catch can never delete the winner's bookkeeping.
    if (this.attachedTabs.has(tabId) || this.attaching.has(tabId)) return;
    // Reserve BEFORE the await — this closes the race window.
    this.attaching.add(tabId);
    try {
      await chrome.debugger.attach({ tabId }, DEBUGGER_PROTOCOL);
      // Mark attached before awaiting enable so a racing detach can find it.
      this.attachedTabs.add(tabId);
      this.tabSessions.set(tabId, new Set());
      await chrome.debugger.sendCommand({ tabId }, 'Network.enable', {
        maxResourceBufferSize: 10 * 1024 * 1024,
        maxTotalBufferSize: 50 * 1024 * 1024,
      });
      // Force-disable cache so response bodies are always fetched fresh from the
      // network (never served from disk cache where getResponseBody returns empty).
      await chrome.debugger.sendCommand({ tabId }, 'Network.setCacheDisabled', {
        cacheDisabled: true,
      });
      // Bypass Service Worker interception so we capture the true network request,
      // not the SW-intercepted version (SW can modify/short-circuit requests).
      await chrome.debugger.sendCommand({ tabId }, 'Network.setBypassServiceWorker', {
        bypass: true,
      });
      // Enable Page domain to capture lifecycle events (navigation, DOMContentLoaded,
      // load) for timeline context.
      await chrome.debugger.sendCommand({ tabId }, 'Page.enable');
      // Enable Runtime domain to capture console messages and JS exceptions.
      await chrome.debugger.sendCommand({ tabId }, 'Runtime.enable');
      // Inject anti-detection script BEFORE any page script runs.
      // Removes navigator.webdriver, patches CDP detection vectors, masks debugger.
      await chrome.debugger.sendCommand({ tabId }, 'Page.addScriptToEvaluateOnNewDocument', {
        source: [
          // Remove webdriver flag
          'try { Object.defineProperty(navigator, "webdriver", { get: () => undefined }); } catch(e) {}',
          // Patch chrome.runtime to look like a normal extension-less page
          'try { window.chrome = window.chrome || {}; if (!chrome.runtime) chrome.runtime = {}; } catch(e) {}',
          // Override Permissions.query to not reveal automation
          'try { const origQuery = window.navigator.permissions.query; window.navigator.permissions.query = (p) => p.name === "notifications" ? Promise.resolve({state: Notification.permission}) : origQuery(p); } catch(e) {}',
          // Mask plugins array to look real
          'try { Object.defineProperty(navigator, "plugins", { get: () => [1,2,3,4,5] }); } catch(e) {}',
          // Mask languages
          'try { Object.defineProperty(navigator, "languages", { get: () => ["en-US","en"] }); } catch(e) {}',
          // Patch WebGL vendor/renderer to avoid headless detection
          'try { const getParameter = WebGLRenderingContext.prototype.getParameter; WebGLRenderingContext.prototype.getParameter = function(p) { if (p === 37445) return "Intel Inc."; if (p === 37446) return "Intel Iris OpenGL Engine"; return getParameter.call(this, p); }; } catch(e) {}',
          // Chrome devtools detection bypass — hide the debugger infobar state
          'try { const devtools = /./; devtools.toString = function() { return ""; }; } catch(e) {}',
        ].join('\n'),
      });
      // Flatten OOPIFs + workers into child sessions so their network traffic
      // (captcha endpoints, cross-origin flows) is visible to us.
      await chrome.debugger.sendCommand({ tabId }, 'Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: WAIT_FOR_DEBUGGER,
        flatten: true,
        filter: CHILD_FILTER,
      });
      console.log('[debugger] attached', tabId);
    } catch (e) {
      // Only the owning attempt reaches here (a genuine failure) — clean up its own state.
      console.warn('[debugger] attach failed', tabId, e);
      this.attachedTabs.delete(tabId);
      this.tabSessions.delete(tabId);
    } finally {
      // Release this attempt's reservation (success or failure) so the tab can re-attach later.
      this.attaching.delete(tabId);
    }
  }

  async detach(tabId: number): Promise<void> {
    if (!this.attachedTabs.has(tabId)) return;
    try {
      await chrome.debugger.detach({ tabId });
    } catch (e) {
      console.warn('[debugger] detach failed', tabId, e);
    }
    this.cleanupTab(tabId);
  }

  async detachAll(): Promise<void> {
    const ids = Array.from(this.attachedTabs);
    for (const id of ids) await this.detach(id);
  }

  isAttached(tabId: number): boolean {
    return this.attachedTabs.has(tabId);
  }

  attachedCount(): number {
    return this.attachedTabs.size;
  }

  // ───────────────────── child-target lifecycle ─────────────────────

  private async onAttachedToTarget(source: SessionTarget, p: any): Promise<void> {
    const sessionId: string = p.sessionId;
    const info = p.targetInfo;
    const waiting: boolean = !!p.waitingForDebugger;
    const childTarget: SessionTarget = { sessionId };

    // Resolve the owning tab: source.tabId for a direct child of the root, else the
    // parent child-session's tabId (nested iframe-in-iframe / worker-in-iframe).
    const parentTabId =
      source.tabId ?? (source.sessionId ? this.sessions.get(source.sessionId)?.tabId : undefined);

    if (parentTabId == null) {
      // Unattributable — still MUST resume so the target doesn't hang.
      await this.safeResume(childTarget, waiting);
      return;
    }

    // Idempotency: attachedToTarget can fire twice for the same target on fast nav.
    if (this.sessions.has(sessionId)) {
      await this.safeResume(childTarget, waiting);
      return;
    }

    this.sessions.set(sessionId, {
      sessionId,
      tabId: parentTabId,
      target: childTarget,
      targetType: info?.type ?? 'other',
    });
    this.tabSessions.get(parentTabId)?.add(sessionId);

    try {
      await chrome.debugger.sendCommand(childTarget, 'Network.enable', {});
      // Force-disable cache on child sessions too (OOPIFs, workers).
      await chrome.debugger.sendCommand(childTarget, 'Network.setCacheDisabled', {
        cacheDisabled: true,
      });
      // Bypass SW on child sessions too.
      await chrome.debugger.sendCommand(childTarget, 'Network.setBypassServiceWorker', {
        bypass: true,
      });
      // Enable Page domain on child sessions for lifecycle events.
      await chrome.debugger.sendCommand(childTarget, 'Page.enable');
      // Enable Runtime on child sessions for console/exception capture.
      await chrome.debugger.sendCommand(childTarget, 'Runtime.enable');
      // Auto-attach is NOT recursive — re-arm on the child so nested OOPIFs/workers
      // (e.g. the reCAPTCHA challenge bframe inside the anchor iframe) attach too.
      await chrome.debugger.sendCommand(childTarget, 'Target.setAutoAttach', {
        autoAttach: true,
        waitForDebuggerOnStart: WAIT_FOR_DEBUGGER,
        flatten: true,
        filter: CHILD_FILTER,
      });
    } catch (e) {
      console.warn('[debugger] child setup failed', sessionId, e);
    } finally {
      // Always release the paused target, even if the setup above threw.
      await this.safeResume(childTarget, waiting);
    }
  }

  private async safeResume(target: SessionTarget, waiting: boolean): Promise<void> {
    if (!waiting) return;
    try {
      await chrome.debugger.sendCommand(target, 'Runtime.runIfWaitingForDebugger', {});
    } catch {
      // Target may already be gone (navigated/closed) — nothing to resume.
    }
  }

  private onDetachedFromTarget(p: any): void {
    const sessionId: string = p.sessionId;
    const info = this.sessions.get(sessionId);
    if (!info) return;
    this.sessions.delete(sessionId);
    this.tabSessions.get(info.tabId)?.delete(sessionId);
    this.dropInFlightForSession(sessionId);
  }

  private cleanupTab(tabId: number): void {
    this.attachedTabs.delete(tabId);
    const sids = this.tabSessions.get(tabId);
    if (sids) {
      for (const sid of sids) {
        this.sessions.delete(sid);
        this.dropInFlightForSession(sid);
      }
    }
    this.tabSessions.delete(tabId);
    // Drop root-session in-flight (key prefix `:`) for this tab.
    for (const [k, f] of this.inFlight) {
      if (f.tabId === tabId && k.startsWith(':')) this.inFlight.delete(k);
    }
  }

  private dropInFlightForSession(sessionId: string): void {
    const prefix = `${sessionId}:`;
    for (const k of this.inFlight.keys()) if (k.startsWith(prefix)) this.inFlight.delete(k);
  }

  // ───────────────────── event routing ─────────────────────

  private handleDetach = (source: chrome.debugger.Debuggee, reason: string) => {
    // onDetach source is a plain Debuggee (tabId) with no sessionId — root teardown.
    if (source.tabId != null) {
      this.cleanupTab(source.tabId);
      console.log('[debugger] detached', source.tabId, reason);
    }
  };

  private handleEvent = (source: SessionTarget, method: string, params?: any) => {
    // Target lifecycle events are delivered on the PARENT session (root or a child),
    // so dispatch them BEFORE any tabId guard.
    if (method === 'Target.attachedToTarget') {
      void this.onAttachedToTarget(source, params);
      return;
    }
    if (method === 'Target.detachedFromTarget') {
      this.onDetachedFromTarget(params);
      return;
    }

    const sessionId = source.sessionId;
    let tabId: number | undefined;
    let sessionTarget: SessionTarget;
    if (sessionId) {
      const info = this.sessions.get(sessionId);
      if (!info) return; // event for an unknown/torn-down child — ignore
      tabId = info.tabId;
      sessionTarget = info.target;
    } else {
      if (source.tabId == null) return;
      tabId = source.tabId;
      sessionTarget = { tabId: source.tabId };
    }

    // Page lifecycle events are delivered on the session; dispatch them for timeline context.
    if (method === 'Page.frameNavigated') {
      this.onPageFrameNavigated(tabId, params);
      return;
    }
    if (method === 'Page.domContentEventFired') {
      this.onPageLifecycleEvent(tabId, params, 'domContentLoaded');
      // Fetch performance metrics after DOMContentLoaded
      void this.collectMetrics(tabId, sessionTarget);
      return;
    }
    if (method === 'Page.loadEventFired') {
      this.onPageLifecycleEvent(tabId, params, 'load');
      // Fetch performance metrics after load
      void this.collectMetrics(tabId, sessionTarget);
      return;
    }
    // Runtime console messages and exceptions
    if (method === 'Runtime.consoleAPICalled') {
      this.onConsoleAPICalled(tabId, params);
      return;
    }
    if (method === 'Runtime.exceptionThrown') {
      this.onExceptionThrown(tabId, params);
      return;
    }

    switch (method) {
      case 'Network.requestWillBeSent':
        this.onRequestWillBeSent(tabId, sessionId, sessionTarget, params);
        break;
      case 'Network.requestWillBeSentExtraInfo':
        this.onRequestWillBeSentExtraInfo(sessionId, params);
        break;
      case 'Network.responseReceived':
        this.onResponseReceived(sessionId, params);
        break;
      case 'Network.responseReceivedExtraInfo':
        this.onResponseReceivedExtraInfo(sessionId, params);
        break;
      case 'Network.loadingFinished':
        void this.onLoadingFinished(sessionId, params);
        break;
      case 'Network.loadingFailed':
        this.onLoadingFailed(sessionId, params);
        break;
      case 'Network.webSocketCreated':
        this.onWebSocketCreated(tabId, sessionId, sessionTarget, params);
        break;
      case 'Network.webSocketWillSendHandshakeRequest':
        this.onWebSocketWillSendHandshakeRequest(sessionId, params);
        break;
      case 'Network.webSocketWillSendHandshakeResponse':
        this.onWebSocketWillSendHandshakeResponse(sessionId, params);
        break;
      case 'Network.webSocketFrameSent':
        this.onWebSocketFrame(sessionId, params, 'sent');
        break;
      case 'Network.webSocketFrameReceived':
        this.onWebSocketFrame(sessionId, params, 'received');
        break;
      case 'Network.webSocketFrameError':
        this.onWebSocketFrameError(sessionId, params);
        break;
      case 'Network.webSocketClosed':
        this.onWebSocketClosed(sessionId, params);
        break;
      case 'Network.eventSourceMessageReceived':
        this.onEventSourceMessage(sessionId, params);
        break;
    }
  };

  private keyFor(sessionId: string | undefined, requestId: string): string {
    return `${sessionId ?? ''}:${requestId}`;
  }

  private trackInFlight(f: InFlight): void {
    this.inFlight.set(f.key, f);
    // INFLIGHT_LIMIT=0 means unlimited — never evict (personal machine capture).
    if (INFLIGHT_LIMIT > 0 && this.inFlight.size > INFLIGHT_LIMIT) {
      const victim = pickEvictionKey(this.inFlight.values());
      if (victim !== undefined) this.inFlight.delete(victim);
    }
  }

  private onRequestWillBeSent(
    tabId: number,
    sessionId: string | undefined,
    target: SessionTarget,
    p: any,
  ): void {
    const reqId = p.requestId as string;
    // Captcha hook runs UNFILTERED for every type (Document/Script/etc.) so iframe
    // captcha script + endpoint loads are detected regardless of capture scope.
    try {
      this.listener.onCaptchaUrl?.(
        p.request.url,
        tabId,
        reqId,
        typeof p.request.postData === 'string' ? p.request.postData : undefined,
      );
    } catch {}

    const rt = mapResourceTypeFull(p.type);
    if (!shouldCapture(rt, this.getScope())) return;

    const key = this.keyFor(sessionId, reqId);

    // Redirects re-emit requestWillBeSent with the SAME requestId and a
    // redirectResponse — surface the hop's status on the existing row.
    if (p.redirectResponse) {
      const existing = this.inFlight.get(key);
      if (existing) {
        // Accumulate the redirect hop — full URL, status, headers, timing.
        const hop: RedirectHop = {
          url: existing.url,
          status: typeof p.redirectResponse.status === 'number' ? p.redirectResponse.status : 0,
          statusText: typeof p.redirectResponse.statusText === 'string' ? p.redirectResponse.statusText : '',
          headers: headersToList(p.redirectResponse.headers),
          timestamp: Date.now(),
        };
        const redirects = [...(existing.redirects ?? []), hop];
        this.listener.onUpdate(existing.id, {
          status: p.redirectResponse.status,
          statusText: p.redirectResponse.statusText,
          redirects,
          ...(p.redirectResponse.headers ? { responseHeaders: headersToList(p.redirectResponse.headers) } : {}),
        });
        existing.redirects = redirects;
      }
    }

    const startedAt = (p.wallTime ?? Date.now() / 1000) * 1000;
    const startMonotonicSec = typeof p.timestamp === 'number' ? p.timestamp : undefined;
    const id = key;
    // Capture the full initiator object (type, url, lineNumber, columnNumber, stack)
    // instead of just the type string — enables tracing request origins.
    const initiator: Initiator | undefined = p.initiator
      ? {
          type: String(p.initiator.type ?? ''),
          ...(p.initiator.url != null ? { url: String(p.initiator.url) } : {}),
          ...(typeof p.initiator.lineNumber === 'number'
            ? { lineNumber: p.initiator.lineNumber }
            : {}),
          ...(typeof p.initiator.columnNumber === 'number'
            ? { columnNumber: p.initiator.columnNumber }
            : {}),
          ...(p.initiator.stack?.callFrames
            ? {
                stack: {
                  callFrames: p.initiator.stack.callFrames.map((cf: any) => ({
                    url: String(cf?.url ?? ''),
                    functionName: String(cf?.functionName ?? ''),
                    lineNumber: typeof cf?.lineNumber === 'number' ? cf.lineNumber : 0,
                    columnNumber: typeof cf?.columnNumber === 'number' ? cf.columnNumber : 0,
                  })),
                },
              }
            : {}),
        }
      : undefined;
    const hasPostData = !!p.request.hasPostData && typeof p.request.postData !== 'string';
    const inflight: InFlight = {
      id,
      key,
      tabId,
      sessionTarget: target,
      type: rt,
      method: p.request.method,
      url: p.request.url,
      host: parseHost(p.request.url),
      startedAt,
      startMonotonicSec,
      requestHeaders: headersToList(p.request.headers),
      requestBody: typeof p.request.postData === 'string' ? p.request.postData : undefined,
      initiator,
      hasPostData,
      redirects: this.inFlight.get(key)?.redirects,
    };
    this.trackInFlight(inflight);
    this.listener.onRequest({
      id,
      tabId,
      type: rt,
      method: inflight.method,
      url: inflight.url,
      host: inflight.host,
      startedAt,
      requestHeaders: inflight.requestHeaders,
      requestBody: inflight.requestBody,
      responseHeaders: [],
      initiator: inflight.initiator,
      // Chrome's resource priority (VeryLow/Low/Medium/High/VeryHigh).
      ...(typeof p.request.initialPriority === 'string' ? { priority: p.request.initialPriority } : {}),
      ...(hasPostData ? { hasPostData: true } : {}),
      ...(inflight.redirects?.length ? { redirects: inflight.redirects } : {}),
    });
  }

  private onResponseReceived(sessionId: string | undefined, p: any): void {
    const f = this.inFlight.get(this.keyFor(sessionId, p.requestId));
    if (!f) return;
    const r = p.response;
    // Extract TLS security details (protocol, cipher, cert issuer/subject/SAN, validity).
    const sd = r.securityDetails;
    const securityDetails: SecurityDetails | undefined = sd
      ? {
          ...(typeof sd.protocol === 'string' ? { protocol: sd.protocol } : {}),
          ...(typeof sd.keyExchange === 'string' ? { keyExchange: sd.keyExchange } : {}),
          ...(typeof sd.keyExchangeGroup === 'string' ? { keyExchangeGroup: sd.keyExchangeGroup } : {}),
          ...(typeof sd.cipher === 'string' ? { cipher: sd.cipher } : {}),
          ...(typeof sd.mac === 'string' ? { mac: sd.mac } : {}),
          ...(sd.issuer?.commonName ? { issuer: String(sd.issuer.commonName) } : {}),
          ...(sd.subject?.commonName ? { subject: String(sd.subject.commonName) } : {}),
          ...(Array.isArray(sd.subjectName) ? { subjectAltNames: sd.subjectName.map(String) } : {}),
          ...(typeof sd.validFrom === 'number' ? { validFrom: sd.validFrom * 1000 } : {}),
          ...(typeof sd.validTo === 'number' ? { validTo: sd.validTo * 1000 } : {}),
          ...(typeof sd.tlsVersion === 'string' ? { tlsVersion: sd.tlsVersion } : {}),
        }
      : undefined;
    // Extract detailed resource timing (DNS, TCP, TLS, TTFB).
    const rt = r.timing;
    const resourceTiming: ResourceTiming | undefined = rt
      ? {
          ...(typeof rt.dnsStart === 'number' ? { dnsStart: rt.dnsStart } : {}),
          ...(typeof rt.dnsEnd === 'number' ? { dnsEnd: rt.dnsEnd } : {}),
          ...(typeof rt.connectStart === 'number' ? { connectStart: rt.connectStart } : {}),
          ...(typeof rt.connectEnd === 'number' ? { connectEnd: rt.connectEnd } : {}),
          ...(typeof rt.sslStart === 'number' ? { tlsStart: rt.sslStart } : {}),
          ...(typeof rt.sslEnd === 'number' ? { tlsEnd: rt.sslEnd } : {}),
          ...(typeof rt.sendStart === 'number' ? { sendStart: rt.sendStart } : {}),
          ...(typeof rt.sendEnd === 'number' ? { sendEnd: rt.sendEnd } : {}),
          ...(typeof rt.receiveHeadersEnd === 'number' ? { receiveHeadersStart: rt.receiveHeadersEnd } : {}),
          ...(typeof rt.receiveHeadersEnd === 'number' && f.startMonotonicSec != null
            ? { ttfbMs: Math.max(0, rt.receiveHeadersEnd) }
            : {}),
        }
      : undefined;
    this.listener.onUpdate(f.id, {
      status: r.status,
      statusText: r.statusText,
      responseHeaders: headersToList(r.headers),
      responseMimeType: r.mimeType,
      fromCache: !!r.fromDiskCache,
      // Server metadata — IP, port, protocol (e.g. "h2", "http/1.1").
      ...(typeof r.remoteIPAddress === 'string' ? { remoteAddress: r.remoteIPAddress } : {}),
      ...(typeof r.remotePort === 'number' ? { remotePort: r.remotePort } : {}),
      ...(typeof r.protocol === 'string' ? { protocol: r.protocol } : {}),
      // TLS security details.
      ...(securityDetails ? { securityDetails } : {}),
      // Detailed resource timing breakdown.
      ...(resourceTiming ? { resourceTiming } : {}),
      // Connection pool metadata.
      ...(typeof r.connectionId === 'number' ? { connectionId: r.connectionId } : {}),
      ...(typeof r.connectionReused === 'boolean' ? { connectionReused: r.connectionReused } : {}),
    });
  }

  /**
   * Network.requestWillBeSentExtraInfo — carries the ACTUAL headers sent over
   * the wire (including cookies the browser added after requestWillBeSent).
   * Merges real headers + extracts cookies into requestCookies.
   */
  private onRequestWillBeSentExtraInfo(sessionId: string | undefined, p: any): void {
    const f = this.inFlight.get(this.keyFor(sessionId, p.requestId));
    if (!f) return;
    const fullHeaders = headersToList(p.headers);
    // Extract Cookie header values into a structured list.
    const cookies: CapturedHeader[] = [];
    for (const h of fullHeaders) {
      if (h.name.toLowerCase() === 'cookie') {
        for (const part of h.value.split(';')) {
          const eq = part.indexOf('=');
          if (eq > 0) {
            cookies.push({
              name: part.slice(0, eq).trim(),
              value: part.slice(eq + 1).trim(),
            });
          }
        }
      }
    }
    this.listener.onUpdate(f.id, {
      requestHeaders: fullHeaders,
      ...(cookies.length ? { requestCookies: cookies } : {}),
    });
  }

  /**
   * Network.responseReceivedExtraInfo — carries the full response headers
   * including Set-Cookie (which Chrome strips from responseReceived).
   * Merges real headers + extracts Set-Cookie into responseCookies.
   */
  private onResponseReceivedExtraInfo(sessionId: string | undefined, p: any): void {
    const f = this.inFlight.get(this.keyFor(sessionId, p.requestId));
    if (!f) return;
    const fullHeaders = headersToList(p.headers);
    // Extract Set-Cookie header values into a structured list.
    const cookies: CapturedHeader[] = [];
    for (const h of fullHeaders) {
      if (h.name.toLowerCase() === 'set-cookie') {
        const eq = h.value.indexOf('=');
        cookies.push({
          name: eq > 0 ? h.value.slice(0, eq).trim() : 'cookie',
          value: h.value,
        });
      }
    }
    this.listener.onUpdate(f.id, {
      responseHeaders: fullHeaders,
      ...(cookies.length ? { responseCookies: cookies } : {}),
    });
  }

  private async onLoadingFinished(sessionId: string | undefined, p: any): Promise<void> {
    const key = this.keyFor(sessionId, p.requestId);
    const f = this.inFlight.get(key);
    if (!f) return;
    // Compute duration/endedAt from ONE monotonic base via cdpDuration (Bug 1). Fall back
    // to a pure-epoch span when the monotonic base is unknown; Date.now() is read ONCE so
    // endedAt and durationMs stay consistent, and the clamp (>= 0) is preserved either way.
    const timing =
      f.startMonotonicSec != null && typeof p.timestamp === 'number'
        ? cdpDuration({
            startedAtEpochMs: f.startedAt,
            startMonotonicSec: f.startMonotonicSec,
            endMonotonicSec: p.timestamp,
          })
        : (() => {
            const now = Date.now();
            return { endedAt: now, durationMs: Math.max(0, now - f.startedAt) };
          })();
    let body: string | undefined;
    let isBase64 = false;
    try {
      // Must address the SAME session the request arrived on, or CDP returns
      // "No resource with given identifier found".
      const r = (await chrome.debugger.sendCommand(f.sessionTarget, 'Network.getResponseBody', {
        requestId: p.requestId,
      })) as any;
      if (r) {
        body = r.body;
        isBase64 = !!r.base64Encoded;
      }
    } catch {
      // Body unavailable (navigation after commit, streamed/worker response, evicted buffer).
    }
    // If the request had post data that wasn't inline (hasPostData flag), fetch it now.
    let postData: string | undefined;
    if (f.hasPostData) {
      try {
        const pd = (await chrome.debugger.sendCommand(f.sessionTarget, 'Network.getRequestPostData', {
          requestId: p.requestId,
        })) as any;
        if (typeof pd?.postData === 'string') {
          postData = pd.postData;
        }
      } catch {
        // Post data may have been evicted from the buffer.
      }
    }
    this.listener.onUpdate(f.id, {
      endedAt: timing.endedAt,
      durationMs: timing.durationMs,
      responseBody: body,
      responseSize: typeof p.encodedDataLength === 'number' ? p.encodedDataLength : undefined,
      // Actual bytes transferred including compressed headers.
      ...(typeof p.encodedDataLength === 'number' ? { encodedDataLength: p.encodedDataLength } : {}),
      // Bug 4: flag base64 separately instead of overwriting responseMimeType. The real
      // content-type set by onResponseReceived (from r.mimeType) is preserved; har.ts reads
      // responseBodyBase64 to set content.encoding while keeping the true mimeType.
      ...(isBase64 ? { responseBodyBase64: true } : {}),
      // Late-arriving post data for requests where Chrome set hasPostData but didn't inline it.
      ...(postData != null ? { requestBody: postData } : {}),
    });
    this.inFlight.delete(key);
  }

  private onLoadingFailed(sessionId: string | undefined, p: any): void {
    const key = this.keyFor(sessionId, p.requestId);
    const f = this.inFlight.get(key);
    if (!f) return;
    const timing =
      f.startMonotonicSec != null && typeof p.timestamp === 'number'
        ? cdpDuration({
            startedAtEpochMs: f.startedAt,
            startMonotonicSec: f.startMonotonicSec,
            endMonotonicSec: p.timestamp,
          })
        : (() => {
            const now = Date.now();
            return { endedAt: now, durationMs: Math.max(0, now - f.startedAt) };
          })();
    this.listener.onUpdate(f.id, {
      failed: true,
      errorText: p.errorText,
      endedAt: timing.endedAt,
      durationMs: timing.durationMs,
      // Blocked reason (mixed content, CSP, CORS, etc.) — more informative than errorText alone.
      ...(typeof p.blockedReason === 'string' ? { blockedReason: p.blockedReason } : {}),
      ...(p.corsErrorStatus ? { corsErrorStatus: String(p.corsErrorStatus.corsError ?? p.corsErrorStatus) } : {}),
    });
    this.inFlight.delete(key);
  }

  /**
   * Runtime.consoleAPICalled — capture console.log/warn/error/info/debug messages
   * with their text, source URL, and line number. Correlates JS console output
   * with network activity for debugging context.
   */
  private onConsoleAPICalled(tabId: number | undefined, p: any): void {
    if (tabId == null) return;
    const type = typeof p.type === 'string' ? p.type : 'log';
    // Concatenate all args into a single text string.
    const args = Array.isArray(p.args) ? p.args : [];
    const text = args
      .map((a: any) => {
        if (typeof a?.value === 'string') return a.value;
        if (typeof a?.description === 'string') return a.description;
        if (a?.unserializableValue) return String(a.unserializableValue);
        if (a?.type === 'undefined') return 'undefined';
        return JSON.stringify(a?.value ?? a) ?? '';
      })
      .join(' ');
    // Extract source location from the first stack frame if available.
    const frame = p.stackTrace?.callFrames?.[0];
    const msg: ConsoleMessage = {
      type: type === 'warning' ? 'warning' : type === 'error' ? 'error' : type === 'info' ? 'info' : type === 'debug' ? 'debug' : 'log',
      text,
      timestamp: Date.now(),
      ...(typeof frame?.url === 'string' ? { url: frame.url } : {}),
      ...(typeof frame?.lineNumber === 'number' ? { lineNumber: frame.lineNumber } : {}),
      ...(typeof frame?.columnNumber === 'number' ? { columnNumber: frame.columnNumber } : {}),
    };
    this.listener.onConsoleMessage?.(tabId, msg);
  }

  /**
   * Runtime.exceptionThrown — capture unhandled JS exceptions with full
   * stack traces. Critical for debugging network failures that throw.
   */
  private onExceptionThrown(tabId: number | undefined, p: any): void {
    if (tabId == null) return;
    const details = p.exceptionDetails ?? {};
    const text =
      typeof details.text === 'string'
        ? details.text
        : details.exception?.description ?? details.exception?.value ?? 'Uncaught exception';
    const frames = details.stackTrace?.callFrames;
    const msg: ConsoleMessage = {
      type: 'exception',
      text,
      timestamp: Date.now(),
      ...(typeof details.url === 'string' ? { url: details.url } : {}),
      ...(typeof details.lineNumber === 'number' ? { lineNumber: details.lineNumber } : {}),
      ...(typeof details.columnNumber === 'number' ? { columnNumber: details.columnNumber } : {}),
      ...(Array.isArray(frames)
        ? {
            stackTrace: frames.map((cf: any) => ({
              url: String(cf?.url ?? ''),
              functionName: String(cf?.functionName ?? ''),
              lineNumber: typeof cf?.lineNumber === 'number' ? cf.lineNumber : 0,
              columnNumber: typeof cf?.columnNumber === 'number' ? cf.columnNumber : 0,
            })),
          }
        : {}),
    };
    this.listener.onConsoleMessage?.(tabId, msg);
  }

  /**
   * Collect performance metrics (Core Web Vitals + memory) via Performance.getMetrics
   * and Runtime.evaluate. Called after DOMContentLoaded and Load events.
   */
  private async collectMetrics(tabId: number | undefined, target: SessionTarget): Promise<void> {
    if (tabId == null) return;
    try {
      // Get Performance metrics (DNS, TCP, TLS timing + paint metrics).
      const perfResult = (await chrome.debugger.sendCommand(target, 'Performance.getMetrics')) as any;
      const metrics = Array.isArray(perfResult?.metrics) ? perfResult.metrics : [];
      const getMetric = (name: string): number | undefined => {
        const m = metrics.find((x: any) => x.name === name);
        return typeof m?.value === 'number' ? m.value : undefined;
      };
      // Get Core Web Vitals via Runtime.evaluate (PerformanceObserver API).
      const vitalsResult = (await chrome.debugger.sendCommand(target, 'Runtime.evaluate', {
        expression: `(function() {
          try {
            var entries = performance.getEntriesByType('navigation');
            var nav = entries[0] || {};
            var paint = performance.getEntriesByType('paint');
            var fcp = paint.find(function(e) { return e.name === 'first-contentful-paint'; });
            return JSON.stringify({
              fcp: fcp ? fcp.startTime : undefined,
              domContentLoaded: nav.domContentLoadedEventEnd,
              loadEvent: nav.loadEventEnd,
              ttfb: nav.responseStart,
              domInteractive: nav.domInteractive,
              transferSize: nav.transferSize,
            });
          } catch(e) { return '{}'; }
        })()`,
        returnByValue: true,
      })) as any;
      const vitals = vitalsResult?.result?.value ? JSON.parse(vitalsResult.result.value) : {};
      // Get JS heap info.
      const heapResult = (await chrome.debugger.sendCommand(target, 'Runtime.evaluate', {
        expression: 'JSON.stringify({ jsHeapSize: performance.memory ? performance.memory.totalJSHeapSize : undefined, jsHeapUsed: performance.memory ? performance.memory.usedJSHeapSize : undefined })',
        returnByValue: true,
      })) as any;
      const heap = heapResult?.result?.value ? JSON.parse(heapResult.result.value) : {};
      const webVitals: WebVitalMetrics = {
        timestamp: Date.now(),
        ...(vitals.fcp != null ? { fcp: Math.round(vitals.fcp) } : {}),
        ...(vitals.ttfb != null ? { ttfb: Math.round(vitals.ttfb) } : {}),
        ...(vitals.domContentLoaded != null ? { domContentLoaded: Math.round(vitals.domContentLoaded) } : {}),
        ...(vitals.loadEvent != null ? { loadEvent: Math.round(vitals.loadEvent) } : {}),
        ...(getMetric('JSHeapTotalSize') != null ? { jsHeapSize: getMetric('JSHeapTotalSize') } : {}),
        ...(getMetric('JSHeapUsedSize') != null ? { jsHeapUsed: getMetric('JSHeapUsedSize') } : {}),
        ...(heap.jsHeapSize != null ? { jsHeapSize: heap.jsHeapSize } : {}),
        ...(heap.jsHeapUsed != null ? { jsHeapUsed: heap.jsHeapUsed } : {}),
      };
      this.listener.onMetrics?.(tabId, webVitals);
    } catch {
      // Performance domain may not be enabled or page already navigated away.
    }
  }

  private onWebSocketCreated(
    tabId: number,
    sessionId: string | undefined,
    target: SessionTarget,
    p: any,
  ): void {
    const reqId = p.requestId as string;
    const url = p.url as string;
    const startedAt = Date.now();
    const key = this.keyFor(sessionId, reqId);
    const id = key;
    const inflight: InFlight = {
      id,
      key,
      tabId,
      sessionTarget: target,
      type: 'WebSocket',
      method: 'GET',
      url,
      host: parseHost(url),
      startedAt,
      requestHeaders: [],
      initiator: p.initiator
        ? { type: String(p.initiator.type ?? '') } as Initiator
        : undefined,
    };
    this.trackInFlight(inflight);
    this.listener.onRequest({
      id,
      tabId,
      type: 'WebSocket',
      method: 'GET',
      url,
      host: inflight.host,
      startedAt,
      requestHeaders: [],
      responseHeaders: [],
      wsMessages: [],
      initiator: inflight.initiator,
    });
  }

  private onWebSocketWillSendHandshakeRequest(sessionId: string | undefined, p: any): void {
    const f = this.inFlight.get(this.keyFor(sessionId, p.requestId));
    if (!f) return;
    // This event carries BOTH timestamp (monotonic) and wallTime (epoch), so it
    // establishes the WS time base. It fires after webSocketCreated created the
    // inFlight entry, so f will exist.
    if (typeof p.timestamp === 'number') f.startMonotonicSec = p.timestamp; // monotonic base
    if (typeof p.wallTime === 'number') f.startedAt = p.wallTime * 1000; // refine epoch base
  }

  private onWebSocketFrame(
    sessionId: string | undefined,
    p: any,
    direction: 'sent' | 'received',
  ): void {
    const f = this.inFlight.get(this.keyFor(sessionId, p.requestId));
    if (!f) return;
    const r = p.response ?? {};
    const payload = typeof r.payloadData === 'string' ? r.payloadData : '';
    // Convert the frame's CDP MonotonicTime to epoch ms via cdpDuration (Bug 1) so the
    // stored timestamp shares the SAME base as startedDateTime; har.ts then emits
    // _webSocketMessages.time = timestamp/1000 as epoch seconds aligned with the entry
    // (Requirement 1.7). Fall back to Date.now() when the monotonic base is unknown
    // (WS pre-handshake) to stay consistent with the epoch base.
    const frameEpochMs =
      f.startMonotonicSec != null && typeof p.timestamp === 'number'
        ? cdpDuration({
            startedAtEpochMs: f.startedAt,
            startMonotonicSec: f.startMonotonicSec,
            endMonotonicSec: p.timestamp,
          }).endedAt
        : Date.now();
    const opcode = typeof r.opcode === 'number' ? r.opcode : 0;
    const msg: WebSocketMessage = {
      direction,
      timestamp: frameEpochMs,
      opcode,
      payload,
      payloadLength: payload.length,
      // Bug 4: mark binary frames (opcode 2) explicitly so har.ts can flag encoding='base64'
      // downstream rather than inferring it solely from the opcode.
      ...(opcode === 2 ? { isBinary: true } : {}),
    };
    this.listener.onWsMessage(f.id, msg);
  }

  private onWebSocketWillSendHandshakeResponse(sessionId: string | undefined, p: any): void {
    const f = this.inFlight.get(this.keyFor(sessionId, p.requestId));
    if (!f) return;
    // This event carries the server's handshake response headers + status.
    const r = p.response ?? {};
    this.listener.onUpdate(f.id, {
      ...(typeof r.status === 'number' ? { wsStatus: r.status } : {}),
      ...(typeof r.statusText === 'string' ? { wsStatusText: r.statusText } : {}),
      ...(r.headers ? { wsResponseHeaders: headersToList(r.headers) } : {}),
    });
  }

  private onWebSocketFrameError(sessionId: string | undefined, p: any): void {
    const f = this.inFlight.get(this.keyFor(sessionId, p.requestId));
    if (!f) return;
    // Capture the protocol-level error text for the WebSocket connection.
    this.listener.onUpdate(f.id, {
      wsError: typeof p.errorMessage === 'string' ? p.errorMessage : 'WebSocket frame error',
    });
  }

  private onEventSourceMessage(sessionId: string | undefined, p: any): void {
    const f = this.inFlight.get(this.keyFor(sessionId, p.requestId));
    if (!f) return;
    // Build an SSE message entry mirroring the WS message pattern.
    const msg: EventSourceMessage = {
      eventName: typeof p.eventName === 'string' ? p.eventName : '',
      eventId: typeof p.eventId === 'string' ? p.eventId : '',
      data: typeof p.data === 'string' ? p.data : '',
      timestamp:
        typeof p.timestamp === 'number'
          ? f.startMonotonicSec != null
            ? cdpDuration({
                startedAtEpochMs: f.startedAt,
                startMonotonicSec: f.startMonotonicSec,
                endMonotonicSec: p.timestamp,
              }).endedAt
            : Date.now()
          : Date.now(),
    };
    this.listener.onSseMessage?.(f.id, msg);
  }

  private onPageFrameNavigated(tabId: number | undefined, p: any): void {
    if (tabId == null) return;
    const frame = p?.frame;
    if (!frame) return;
    // Only emit navigation events for the top-level frame to avoid noise from
    // every subframe navigate.
    if (!frame.parentId) {
      this.listener.onPageEvent?.(tabId, {
        type: 'navigation',
        timestamp: Date.now(),
        url: typeof frame.url === 'string' ? frame.url : undefined,
        frameId: typeof frame.id === 'string' ? frame.id : undefined,
      });
    }
  }

  private onPageLifecycleEvent(
    tabId: number | undefined,
    p: any,
    type: 'domContentLoaded' | 'load',
  ): void {
    if (tabId == null) return;
    this.listener.onPageEvent?.(tabId, {
      type,
      timestamp:
        typeof p.timestamp === 'number'
          ? Date.now() // Page lifecycle timestamps are monotonic; use epoch for simplicity
          : Date.now(),
    });
  }

  private onWebSocketClosed(sessionId: string | undefined, p: any): void {
    const key = this.keyFor(sessionId, p.requestId);
    const f = this.inFlight.get(key);
    if (!f) return;
    const timing =
      f.startMonotonicSec != null && typeof p.timestamp === 'number'
        ? cdpDuration({
            startedAtEpochMs: f.startedAt,
            startMonotonicSec: f.startMonotonicSec,
            endMonotonicSec: p.timestamp,
          })
        : (() => {
            const now = Date.now();
            return { endedAt: now, durationMs: Math.max(0, now - f.startedAt) };
          })();
    this.listener.onUpdate(f.id, {
      endedAt: timing.endedAt,
      durationMs: timing.durationMs,
    });
    this.inFlight.delete(key);
  }
}
