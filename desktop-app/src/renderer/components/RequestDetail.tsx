import { Fragment, useState, type ReactNode } from 'react';
import { Tabs, TextInput, Text } from '@mantine/core';
import type { CapturedRequest, CapturedHeader } from '@har-suite/shared';

type Tab = 'headers' | 'payload' | 'response' | 'ws' | 'sse' | 'script';

function HeaderTable({ headers, highlight }: { headers: CapturedHeader[]; highlight?: string }) {
  if (!headers.length) return <Text c="dimmed">(no headers)</Text>;
  return (
    <div className="kv">
      {headers.map((h, i) => (
        <Fragment key={i}>
          <div className="k">{h.name}</div>
          <div className="v">{highlightText(h.value, highlight)}</div>
        </Fragment>
      ))}
    </div>
  );
}

function highlightText(text: string, query: string | undefined): ReactNode {
  const q = (query ?? '').trim();
  if (!q) return text;
  const lower = text.toLowerCase();
  const ql = q.toLowerCase();
  const out: ReactNode[] = [];
  let i = 0;
  let idx = lower.indexOf(ql);
  while (idx !== -1) {
    if (idx > i) out.push(text.slice(i, idx));
    out.push(
      <mark key={`m-${idx}`} className="hl">
        {text.slice(idx, idx + ql.length)}
      </mark>,
    );
    i = idx + ql.length;
    idx = lower.indexOf(ql, i);
  }
  if (i < text.length) out.push(text.slice(i));
  return out;
}

function tryPretty(text: string, mime: string | undefined): string {
  const m = (mime ?? '').toLowerCase();
  if (m.includes('json') || text.trim().startsWith('{') || text.trim().startsWith('[')) {
    try {
      return JSON.stringify(JSON.parse(text), null, 2);
    } catch {}
  }
  return text;
}

export default function RequestDetail({
  request,
  highlight,
}: {
  request: CapturedRequest;
  highlight?: string;
}) {
  const [tab, setTab] = useState<Tab>('headers');
  const [wsFilter, setWsFilter] = useState('');
  const [sseFilter, setSseFilter] = useState('');
  const isWs = request.type === 'WebSocket';
  const isSse = request.type === 'EventSource';

  const filteredWs = (request.wsMessages ?? []).filter(
    (m) => !wsFilter || m.payload.toLowerCase().includes(wsFilter.toLowerCase()),
  );

  const filteredSse = (request.eventSourceMessages ?? []).filter(
    (m) => !sseFilter || m.data.toLowerCase().includes(sseFilter.toLowerCase()),
  );

  // Format initiator for display — may be a string (legacy) or object.
  const initiatorDisplay = (() => {
    if (!request.initiator) return '-';
    if (typeof request.initiator === 'string') return request.initiator;
    const ini = request.initiator;
    let s = ini.type;
    if (ini.url) s += ` · ${ini.url}`;
    if (ini.lineNumber != null) s += `:${ini.lineNumber}`;
    return s;
  })();

  const contentType = request.requestHeaders.find(
    (h) => h.name.toLowerCase() === 'content-type',
  )?.value;

  return (
    <div>
      <div className="kv" style={{ marginBottom: 8 }}>
        <div className="k">URL</div>
        <div className="v">{request.url}</div>
        <div className="k">Method</div>
        <div className="v">{request.method}</div>
        <div className="k">Status</div>
        <div className="v">
          {request.failed
            ? `Failed: ${request.errorText}`
            : `${request.status ?? '...'} ${request.statusText ?? ''}`}
        </div>
        <div className="k">Type</div>
        <div className="v">{request.type}</div>
        <div className="k">Duration</div>
        <div className="v">
          {request.durationMs != null ? `${request.durationMs.toFixed(0)} ms` : '-'}
        </div>
        <div className="k">Initiator</div>
        <div className="v">{initiatorDisplay}</div>
        {request.remoteAddress && (
          <>
            <div className="k">Server</div>
            <div className="v">
              {request.remoteAddress}
              {request.remotePort != null ? `:${request.remotePort}` : ''}
              {request.protocol ? ` (${request.protocol})` : ''}
            </div>
          </>
        )}
        {request.wsError && (
          <>
            <div className="k">WS Error</div>
            <div className="v" style={{ color: 'var(--mantine-color-red-text)' }}>{request.wsError}</div>
          </>
        )}
        {request.priority && (
          <>
            <div className="k">Priority</div>
            <div className="v">{request.priority}</div>
          </>
        )}
        {request.connectionId != null && (
          <>
            <div className="k">Connection</div>
            <div className="v">
              #{request.connectionId}
              {request.connectionReused != null
                ? request.connectionReused
                  ? ' (reused)'
                  : ' (new)'
                : ''}
            </div>
          </>
        )}
        {request.encodedDataLength != null && (
          <>
            <div className="k">Wire Size</div>
            <div className="v">{request.encodedDataLength.toLocaleString()} bytes</div>
          </>
        )}
        {request.blockedReason && (
          <>
            <div className="k">Blocked</div>
            <div className="v" style={{ color: 'var(--mantine-color-red-text)' }}>{request.blockedReason}</div>
          </>
        )}
        {request.corsErrorStatus && (
          <>
            <div className="k">CORS Error</div>
            <div className="v" style={{ color: 'var(--mantine-color-red-text)' }}>{request.corsErrorStatus}</div>
          </>
        )}
        {request.securityDetails && (
          <>
            <div className="k">TLS</div>
            <div className="v">
              {request.securityDetails.tlsVersion ?? request.securityDetails.protocol ?? '-'}
              {request.securityDetails.cipher ? ` · ${request.securityDetails.cipher}` : ''}
            </div>
            {request.securityDetails.issuer && (
              <>
                <div className="k">Cert Issuer</div>
                <div className="v">{request.securityDetails.issuer}</div>
              </>
            )}
            {request.securityDetails.validTo && (
              <>
                <div className="k">Cert Expiry</div>
                <div className="v">{new Date(request.securityDetails.validTo).toISOString().slice(0, 10)}</div>
              </>
            )}
          </>
        )}
        {request.resourceTiming && (
          <>
            <div className="k">Timing</div>
            <div className="v">
              {[
                request.resourceTiming.dnsEnd != null && request.resourceTiming.dnsStart != null
                  ? `DNS ${Math.max(0, request.resourceTiming.dnsEnd - request.resourceTiming.dnsStart).toFixed(0)}ms`
                  : null,
                request.resourceTiming.connectEnd != null && request.resourceTiming.connectStart != null
                  ? `TCP ${Math.max(0, request.resourceTiming.connectEnd - request.resourceTiming.connectStart).toFixed(0)}ms`
                  : null,
                request.resourceTiming.tlsEnd != null && request.resourceTiming.tlsStart != null
                  ? `TLS ${Math.max(0, request.resourceTiming.tlsEnd - request.resourceTiming.tlsStart).toFixed(0)}ms`
                  : null,
                request.resourceTiming.ttfbMs != null
                  ? `TTFB ${request.resourceTiming.ttfbMs.toFixed(0)}ms`
                  : null,
              ].filter(Boolean).join(' · ') || '-'}
            </div>
          </>
        )}
        {request.redirects && request.redirects.length > 0 && (
          <>
            <div className="k">Redirects</div>
            <div className="v">{request.redirects.length} hop(s)</div>
          </>
        )}
      </div>

      <Tabs value={tab} onChange={(v) => setTab((v as Tab) ?? 'headers')} mb="sm">
        <Tabs.List>
          <Tabs.Tab value="headers">Headers</Tabs.Tab>
          {!isWs && <Tabs.Tab value="payload">Payload</Tabs.Tab>}
          {!isWs && <Tabs.Tab value="response">Response</Tabs.Tab>}
          {request.type === 'Script' && <Tabs.Tab value="script">Script</Tabs.Tab>}
          {isWs && <Tabs.Tab value="ws">Messages ({request.wsMessages?.length ?? 0})</Tabs.Tab>}
          {isSse && <Tabs.Tab value="sse">SSE ({request.eventSourceMessages?.length ?? 0})</Tabs.Tab>}
        </Tabs.List>

        <Tabs.Panel value="headers" pt="sm">
          <Text size="sm" fw={600} c="dimmed" mb={4}>
            Request Headers
          </Text>
          <HeaderTable headers={request.requestHeaders} highlight={highlight} />
          <Text size="sm" fw={600} c="dimmed" mt="md" mb={4}>
            Response Headers
          </Text>
          <HeaderTable headers={request.responseHeaders} highlight={highlight} />
        </Tabs.Panel>

        {!isWs && (
          <Tabs.Panel value="payload" pt="sm">
            {request.requestBody ? (
              <pre>{highlightText(tryPretty(request.requestBody, contentType), highlight)}</pre>
            ) : (
              <Text c="dimmed">(no request body)</Text>
            )}
          </Tabs.Panel>
        )}

        {!isWs && (
          <Tabs.Panel value="response" pt="sm">
            {request.responseBody ? (
              <pre>
                {highlightText(
                  tryPretty(request.responseBody, request.responseMimeType),
                  highlight,
                )}
              </pre>
            ) : (
              <Text c="dimmed">(no response body — may not have finished, or body was binary)</Text>
            )}
          </Tabs.Panel>
        )}

        {request.type === 'Script' && (
          <Tabs.Panel value="script" pt="sm">
            {request.responseBody ? (
              <div style={{ position: 'relative' }}>
                <pre style={{ maxHeight: '600px', overflow: 'auto', fontSize: '12px', lineHeight: '1.5' }}>
                  {highlightText(request.responseBody, highlight)}
                </pre>
              </div>
            ) : (
              <Text c="dimmed">(no script content — body may not be available)</Text>
            )}
          </Tabs.Panel>
        )}

        {isWs && (
          <Tabs.Panel value="ws" pt="sm">
            <TextInput
              placeholder="Filter messages…"
              value={wsFilter}
              onChange={(e) => setWsFilter(e.currentTarget.value)}
              mb="sm"
            />
            {filteredWs.length === 0 ? (
              <Text c="dimmed">
                {(request.wsMessages ?? []).length === 0
                  ? '(no messages yet)'
                  : '(no messages match filter)'}
              </Text>
            ) : (
              filteredWs.map((m, i) => (
                <div key={i} className={`ws-frame ${m.direction}`}>
                  <div className="meta">
                    {m.direction.toUpperCase()} · opcode {m.opcode} · {m.payloadLength} bytes ·{' '}
                    {new Date(m.timestamp).toISOString()}
                  </div>
                  <div>
                    {highlightText(
                      m.payload.slice(0, 4000) + (m.payload.length > 4000 ? '...' : ''),
                      wsFilter || highlight,
                    )}
                  </div>
                </div>
              ))
            )}
          </Tabs.Panel>
        )}
        {isSse && (
          <Tabs.Panel value="sse" pt="sm">
            <TextInput
              placeholder="Filter SSE messages…"
              value={sseFilter}
              onChange={(e) => setSseFilter(e.currentTarget.value)}
              mb="sm"
            />
            {filteredSse.length === 0 ? (
              <Text c="dimmed">
                {(request.eventSourceMessages ?? []).length === 0
                  ? '(no SSE messages yet)'
                  : '(no messages match filter)'}
              </Text>
            ) : (
              filteredSse.map((m, i) => (
                <div key={i} className="ws-frame received">
                  <div className="meta">
                    {m.eventName || '(default)'} · id: {m.eventId || '-'} ·{' '}
                    {new Date(m.timestamp).toISOString()}
                  </div>
                  <div>
                    {highlightText(
                      m.data.slice(0, 4000) + (m.data.length > 4000 ? '...' : ''),
                      sseFilter || highlight,
                    )}
                  </div>
                </div>
              ))
            )}
          </Tabs.Panel>
        )}
      </Tabs>
    </div>
  );
}
