import * as mockttp from 'mockttp';
import type {
  CapturedRequest,
  CapturedHeader,
  CaptureScope,
  WebSocketMessage,
  CaptchaDetection,
  Initiator,
} from '@har-suite/shared';
import {
  inferResourceType,
  mitmIngestGate,
  detectFromUrl,
  shouldCaptureApp,
  IdRegistry,
  buildWsRow,
  wsCloseTiming,
} from '@har-suite/shared';
import type { CaPair } from './ca-trust';
import { lookupProcess } from './process-resolver';

// Bodies larger than this are truncated to keep memory/db sane. Mirrors the
// spirit of the CDP path (Chrome also caps retained bodies).
const MAX_BODY_BYTES = 5 * 1024 * 1024;

export interface CaptureSink {
  onRequest(req: CapturedRequest): void;
  onUpdate(id: string, patch: Partial<CapturedRequest>): void;
  onWsMessage(id: string, msg: WebSocketMessage): void;
  onCaptchaDetected?(detection: CaptchaDetection): void;
}

function rawHeadersToList(raw: Array<[string, string]> | undefined): CapturedHeader[] {
  if (!raw) return [];
  return raw.map(([name, value]) => ({ name, value }));
}

function headerValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const v = headers[name];
  if (Array.isArray(v)) return v[0];
  return v;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
}

/**
 * Captures native-app HTTP(S) traffic through an embedded mockttp MITM proxy
 * and feeds it into the SAME ingestion sink the Chrome-extension bridge uses,
 * so app rows share storage, the renderer list, and HAR export with web rows.
 */
export class MitmCapture {
  private server: mockttp.Mockttp | null = null;
  private counter = 0;
  private running = false;
  // mockttp event id → our namespaced public CapturedRequest id. IdRegistry
  // wraps the Map + INFLIGHT_LIMIT eviction (extracted to @har-suite/shared so
  // the WebSocket seams can be unit-tested); a single internal instance is
  // shared by the HTTP and WS paths. Not readonly: stop() swaps in a fresh
  // registry to clear all mappings (IdRegistry exposes no clear()).
  private ids = new IdRegistry();
  // mockttp event id → origin process info (captured at request-initiated, used at request).
  private pendingOrigins = new Map<string, { pid: number; exe: string }>();
  // Recently seen executable names (for UI autocomplete in app filter dialog).
  private seenExes = new Set<string>();

  constructor(
    private readonly sink: CaptureSink,
    private readonly getScope: () => CaptureScope,
    private readonly getAppFilter: () => { allowlist: string[]; bypass: boolean },
    private readonly getCaptureEnabled: () => boolean,
  ) {}

  isRunning(): boolean {
    return this.running;
  }

  getSeenExes(): string[] {
    return Array.from(this.seenExes).sort();
  }

  async start(port: number, ca: CaPair): Promise<void> {
    if (this.running) return;
    const server = mockttp.getLocal({
      https: { key: ca.key, cert: ca.cert },
      // Record full request/response bodies so the captured rows carry payloads.
      recordTraffic: true,
    });
    this.server = server;

    // Transparent proxy: forward everything to its real destination unchanged.
    await server.forAnyRequest().thenPassThrough();
    await server.forAnyWebSocket().thenPassThrough();

    // Capture process info early (while connection is still open) before 'request' fires.
    await server.on('request-initiated', (req) => this.onRequestInitiated(req));
    await server.on('request', (req) => this.onRequest(req));
    await server.on('response', (res) => this.onResponse(res));
    await server.on('websocket-message-received', (m) => this.onWsMessage(m, 'received'));
    await server.on('websocket-message-sent', (m) => this.onWsMessage(m, 'sent'));
    // Bug 4: a WebSocket upgrade does NOT fire 'request', so subscribe to the
    // dedicated WS events. 'websocket-request' creates the row + registers the
    // id (so onWsMessage frames map to it), 'websocket-accepted' fills status,
    // and 'websocket-close' fills endedAt/durationMs (design §4.4).
    await server.on('websocket-request', (req) => this.onWebSocketRequest(req));
    await server.on('websocket-accepted', (res) => this.onWebSocketAccepted(res));
    await server.on('websocket-close', (close) => this.onWebSocketClose(close));

    await server.start(port);
    this.running = true;
  }

  async stop(): Promise<void> {
    this.running = false;
    this.ids = new IdRegistry();
    this.pendingOrigins.clear();
    const s = this.server;
    this.server = null;
    if (s) {
      try {
        await s.stop();
      } catch {
        // Already stopping/stopped — fine.
      }
    }
  }

  private onRequestInitiated(req: mockttp.Request): void {
    // Look up the originating process by matching the client's ephemeral port
    // against the Windows TCP table. Must happen while the connection is still open.
    const info = lookupProcess(req.remotePort);
    if (info) {
      this.pendingOrigins.set(req.id, info);
      this.seenExes.add(info.exe);
      // Keep seenExes bounded (last 100 unique executables).
      if (this.seenExes.size > 100) {
        const oldest = Array.from(this.seenExes).slice(0, this.seenExes.size - 100);
        oldest.forEach((exe) => this.seenExes.delete(exe));
      }
    }
  }

  private onRequest(req: mockttp.CompletedRequest): void {
    // ── Bug 3: master pause ──
    // When the global Capture toggle is OFF there is no MITM ingestion: no
    // persist, no renderer push, AND captcha detection is skipped. This must be
    // first so it also gates the captcha block below.
    if (!this.getCaptureEnabled()) return;

    // Pop the origin info captured at request-initiated (if available).
    const origin = this.pendingOrigins.get(req.id);
    this.pendingOrigins.delete(req.id);

    const url = req.url;

    // ── Captcha detection (runs on ALL requests, even filtered ones) ──
    // Infer page context from Referer header (native apps may not send it,
    // but browser-based traffic through the proxy will).
    const referer = headerValue(req.headers, 'referer') ?? '';
    let pageUrl = referer;
    let pageHost = '';
    try {
      pageHost = referer ? new URL(referer).host : '';
    } catch {}

    if (this.sink.onCaptchaDetected) {
      const detection = detectFromUrl({
        url,
        pageUrl,
        pageHost,
        requestId: req.id,
      });
      if (detection) {
        this.sink.onCaptchaDetected(detection);
      }
    }

    // ── HAR capture scope + filter ──
    const type = inferResourceType({
      secFetchDest: headerValue(req.headers, 'sec-fetch-dest'),
      contentType: headerValue(req.headers, 'content-type'),
      upgrade: headerValue(req.headers, 'upgrade'),
      url,
    });
    // captureEnabled is passed as true here because the master-pause is already
    // handled by the early return at the top of onRequest; mitmIngestGate then
    // applies the scope + app-filter decision.
    const { allowlist, bypass } = this.getAppFilter();
    const exeName = origin?.exe ?? '';
    if (
      !mitmIngestGate({
        captureEnabled: true,
        type,
        scope: this.getScope(),
        exe: exeName,
        allowlist,
        bypass,
      })
    )
      return;

    const id = `app:${this.counter++}`;
    this.ids.remember(req.id, id);

    const startedAt = req.timingEvents?.startTime ?? Date.now();
    const captured: CapturedRequest = {
      id,
      tabId: -1,
      source: 'app',
      originProcess: origin,
      type,
      method: req.method,
      url,
      host: hostOf(url) || req.hostname || '',
      startedAt,
      requestHeaders: rawHeadersToList(req.rawHeaders),
      responseHeaders: [],
      initiator: { type: 'app' } as Initiator,
    };

    // Attach request body asynchronously (decoded), then emit.
    void req.body
      .getText()
      .then((text) => {
        if (text) captured.requestBody = truncate(text);
      })
      .catch(() => undefined)
      .finally(() => this.sink.onRequest(captured));
  }

  private onResponse(res: mockttp.CompletedResponse): void {
    const id = this.ids.get(res.id);
    if (!id) return;

    const endedAt = res.timingEvents?.responseSentTimestamp
      ? (res.timingEvents.startTime ?? 0) +
        (res.timingEvents.responseSentTimestamp - (res.timingEvents.startTimestamp ?? 0))
      : Date.now();
    const startTimestamp = res.timingEvents?.startTimestamp;
    const sentTimestamp = res.timingEvents?.responseSentTimestamp;
    const durationMs =
      startTimestamp != null && sentTimestamp != null
        ? Math.max(0, sentTimestamp - startTimestamp)
        : undefined;

    const responseHeaders = rawHeadersToList(res.rawHeaders);
    const mimeType = headerValue(res.headers, 'content-type');

    void res.body
      .getDecodedBuffer()
      .then((buf) => {
        const patch: Partial<CapturedRequest> = {
          status: res.statusCode,
          statusText: res.statusMessage,
          responseHeaders,
          responseMimeType: mimeType,
          endedAt,
          durationMs,
        };
        if (buf && buf.length) {
          const sliced = buf.length > MAX_BODY_BYTES ? buf.subarray(0, MAX_BODY_BYTES) : buf;
          if (isProbablyText(mimeType)) {
            patch.responseBody = sliced.toString('utf8');
          } else {
            patch.responseBody = sliced.toString('base64');
            patch.responseMimeType = 'application/octet-stream;base64';
          }
          patch.responseSize = buf.length;
        }
        this.sink.onUpdate(id, patch);
      })
      .catch(() => {
        this.sink.onUpdate(id, {
          status: res.statusCode,
          statusText: res.statusMessage,
          responseHeaders,
          responseMimeType: mimeType,
          endedAt,
          durationMs,
        });
      });
  }

  private onWebSocketRequest(req: mockttp.CompletedRequest): void {
    // Pop the origin info captured at request-initiated (if available), same as
    // onRequest — a WS upgrade goes through the request-initiated lookup too.
    const origin = this.pendingOrigins.get(req.id);
    this.pendingOrigins.delete(req.id);

    // ── Bug 3: master pause also applies to WebSocket upgrades ──
    if (!this.getCaptureEnabled()) return;

    // 'WebSocket' is never in the data denylist, so the scope gate always
    // passes; still apply the per-app filter to stay consistent with onRequest.
    const { allowlist, bypass } = this.getAppFilter();
    if (!shouldCaptureApp(origin?.exe ?? '', allowlist, bypass)) return;

    const id = `app:${this.counter++}`;
    this.ids.remember(req.id, id); // register mapping so onWsMessage finds the id

    // buildWsRow is pure/mockttp-free (§4.4); it leaves process attribution to
    // the caller, so attach originProcess here just like onRequest does for HTTP.
    const row = buildWsRow(
      {
        id: req.id,
        url: req.url,
        method: req.method,
        hostname: req.hostname,
        rawHeaders: req.rawHeaders,
        timingEvents: req.timingEvents,
      },
      id,
    );
    row.originProcess = origin;
    this.sink.onRequest(row);
  }

  private onWebSocketAccepted(res: mockttp.CompletedResponse): void {
    const id = this.ids.get(res.id);
    if (!id) return;
    this.sink.onUpdate(id, {
      status: res.statusCode,
      statusText: res.statusMessage,
      responseHeaders: rawHeadersToList(res.rawHeaders),
    });
  }

  private onWebSocketClose(close: mockttp.WebSocketClose): void {
    const id = this.ids.get(close.streamId);
    if (!id) return;
    const { endedAt, durationMs } = wsCloseTiming(close.timingEvents);
    this.sink.onUpdate(id, { endedAt, durationMs });
  }

  private onWsMessage(m: mockttp.WebSocketMessage, direction: 'sent' | 'received'): void {
    const id = this.ids.get(m.streamId);
    if (!id) return;
    const content = Buffer.from(m.content);
    const msg: WebSocketMessage = {
      direction,
      timestamp: Date.now(),
      opcode: m.isBinary ? 2 : 1,
      payload: m.isBinary ? content.toString('base64') : content.toString('utf8'),
      payloadLength: content.length,
    };
    this.sink.onWsMessage(id, msg);
  }
}

function truncate(text: string): string {
  if (text.length <= MAX_BODY_BYTES) return text;
  return text.slice(0, MAX_BODY_BYTES);
}

function isProbablyText(mime: string | undefined): boolean {
  if (!mime) return true; // assume text when unknown
  const m = mime.toLowerCase();
  return (
    m.startsWith('text/') ||
    m.includes('json') ||
    m.includes('xml') ||
    m.includes('javascript') ||
    m.includes('ecmascript') ||
    m.includes('urlencoded') ||
    m.includes('html') ||
    m.includes('csv') ||
    m === 'application/x-ndjson'
  );
}
