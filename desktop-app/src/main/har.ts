import type { CapturedRequest } from '@har-suite/shared';

const HAR_VERSION = '1.2';
const CREATOR = { name: 'HAR Capture Suite', version: '0.1.0' };

function isoTime(ms: number): string {
  return new Date(ms).toISOString();
}

function parseUrlParts(url: string) {
  try {
    const u = new URL(url);
    const queryString = Array.from(u.searchParams.entries()).map(([name, value]) => ({
      name,
      value,
    }));
    return { queryString };
  } catch {
    return { queryString: [] as { name: string; value: string }[] };
  }
}

function bodySizeOf(body?: string): number {
  if (!body) return -1;
  return new TextEncoder().encode(body).length;
}

function buildEntry(req: CapturedRequest) {
  const { queryString } = parseUrlParts(req.url);
  const startedDateTime = isoTime(req.startedAt);
  const time = req.durationMs ?? 0;

  const postData = req.requestBody
    ? {
        mimeType:
          req.requestHeaders.find((h) => h.name.toLowerCase() === 'content-type')?.value ??
          'text/plain',
        text: req.requestBody,
      }
    : undefined;

  const isBase64 =
    req.responseBodyBase64 === true || // new-style flag (real content-type retained)
    req.responseMimeType === 'application/octet-stream;base64'; // legacy magic string
  const content: Record<string, unknown> = {
    size: req.responseSize ?? bodySizeOf(req.responseBody),
    mimeType: req.responseMimeType ?? '',
    text: req.responseBody ?? '',
  };
  if (isBase64) content.encoding = 'base64';

  return {
    startedDateTime,
    time,
    request: {
      method: req.method,
      url: req.url,
      httpVersion: req.protocol ?? 'HTTP/1.1',
      cookies: req.requestCookies ?? [],
      headers: req.requestHeaders,
      queryString,
      headersSize: -1,
      bodySize: bodySizeOf(req.requestBody),
      ...(postData ? { postData } : {}),
    },
    response: {
      status: req.status ?? 0,
      statusText: req.statusText ?? '',
      httpVersion: req.protocol ?? 'HTTP/1.1',
      cookies: req.responseCookies ?? [],
      headers: req.responseHeaders,
      content,
      redirectURL: '',
      headersSize: -1,
      bodySize: req.responseSize ?? -1,
    },
    cache: {},
    timings: {
      send: 0,
      wait: time,
      receive: 0,
    },
    _resourceType: req.type,
    _initiator: req.initiator,
    // Server metadata
    ...(req.remoteAddress ? { _remoteAddress: req.remoteAddress } : {}),
    ...(req.remotePort != null ? { _remotePort: req.remotePort } : {}),
    ...(req.protocol ? { _protocol: req.protocol } : {}),
    // WebSocket extras
    ...(req.type === 'WebSocket' && req.wsMessages
      ? {
          _webSocketMessages: req.wsMessages.map((m) => ({
            type: m.direction === 'sent' ? 'send' : 'receive',
            time: m.timestamp / 1000,
            opcode: m.opcode,
            data: m.payload,
            ...(m.isBinary || m.opcode === 2 ? { encoding: 'base64' } : {}), // dual-path
          })),
        }
      : {}),
    ...(req.wsError ? { _webSocketError: req.wsError } : {}),
    ...(req.wsStatus != null ? { _webSocketStatus: req.wsStatus } : {}),
    ...(req.wsStatusText ? { _webSocketStatusText: req.wsStatusText } : {}),
    ...(req.wsResponseHeaders ? { _webSocketResponseHeaders: req.wsResponseHeaders } : {}),
    // SSE messages
    ...(req.eventSourceMessages?.length
      ? {
          _eventSourceMessages: req.eventSourceMessages.map((m) => ({
            event: m.eventName,
            id: m.eventId,
            data: m.data,
            time: m.timestamp / 1000,
          })),
        }
      : {}),
  };
}

export function buildHar(requests: CapturedRequest[]) {
  return {
    log: {
      version: HAR_VERSION,
      creator: CREATOR,
      pages: [],
      entries: requests
        .slice()
        .sort((a, b) => a.startedAt - b.startedAt)
        .map(buildEntry),
    },
  };
}
