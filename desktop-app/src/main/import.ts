import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import type { CapturedRequest, CapturedHeader, WebSocketMessage } from '@har-suite/shared';
import { mapResourceTypeFull } from '@har-suite/shared';

function asHeaders(v: any): CapturedHeader[] {
  if (!Array.isArray(v)) return [];
  return v.map((h) => ({ name: String(h?.name ?? ''), value: String(h?.value ?? '') }));
}

function parseHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
}

function harEntryToRequest(entry: any, idx: number): CapturedRequest {
  const startedAt = new Date(entry.startedDateTime).getTime();
  const time = typeof entry.time === 'number' ? entry.time : 0;
  const req = entry.request ?? {};
  const res = entry.response ?? {};
  // Prefer our own _resourceType marker (full CDP enum); fall back to Other.
  const type = mapResourceTypeFull(entry._resourceType);
  const content = res.content ?? {};
  let responseBody: string | undefined =
    typeof content.text === 'string' ? content.text : undefined;
  if (responseBody && content.encoding === 'base64') {
    // Keep as base64 with marker mime; the UI handles this.
  }
  const wsMessages: WebSocketMessage[] = Array.isArray(entry._webSocketMessages)
    ? entry._webSocketMessages.map((m: any) => ({
        direction: m.type === 'send' ? 'sent' : 'received',
        timestamp: (typeof m.time === 'number' ? m.time : 0) * 1000,
        opcode: typeof m.opcode === 'number' ? m.opcode : 0,
        payload: String(m.data ?? ''),
        payloadLength: String(m.data ?? '').length,
      }))
    : [];
  return {
    id: `import-${idx}-${randomBytes(6).toString('hex')}`,
    tabId: -1,
    type,
    method: String(req.method ?? 'GET'),
    url: String(req.url ?? ''),
    host: parseHost(String(req.url ?? '')),
    startedAt,
    endedAt: startedAt + time,
    durationMs: time,
    status: typeof res.status === 'number' ? res.status : undefined,
    statusText: typeof res.statusText === 'string' ? res.statusText : undefined,
    requestHeaders: asHeaders(req.headers),
    requestBody: typeof req.postData?.text === 'string' ? req.postData.text : undefined,
    responseHeaders: asHeaders(res.headers),
    responseBody,
    responseMimeType:
      content.encoding === 'base64'
        ? 'application/octet-stream;base64'
        : (content.mimeType ?? undefined),
    responseSize: typeof res.bodySize === 'number' && res.bodySize >= 0 ? res.bodySize : undefined,
    initiator: typeof entry._initiator === 'string'
      ? entry._initiator
      : entry._initiator && typeof entry._initiator === 'object'
        ? { type: String(entry._initiator.type ?? '') }
        : undefined,
    wsMessages: wsMessages.length ? wsMessages : undefined,
  };
}

export async function importHarFile(path: string): Promise<CapturedRequest[]> {
  const text = await readFile(path, 'utf8');
  const parsed = JSON.parse(text);
  const entries = parsed?.log?.entries;
  if (!Array.isArray(entries)) throw new Error('Not a valid HAR file (missing log.entries)');
  return entries.map((e: any, i: number) => harEntryToRequest(e, i));
}
