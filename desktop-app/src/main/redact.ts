import type { CapturedRequest, CapturedHeader, RedactionConfig } from '@har-suite/shared';
import { REDACTED_VALUE } from '@har-suite/shared';

function maskHeaders(headers: CapturedHeader[], patterns: string[]): CapturedHeader[] {
  const lower = patterns.map((p) => p.toLowerCase());
  return headers.map((h) => {
    if (lower.some((p) => h.name.toLowerCase().includes(p))) {
      return { name: h.name, value: REDACTED_VALUE };
    }
    return h;
  });
}

function maskBody(body: string | undefined, patterns: string[]): string | undefined {
  if (!body) return body;
  let out = body;
  for (const p of patterns) {
    if (!p) continue;
    const re = new RegExp(`("${escapeRegExp(p)}"\\s*:\\s*)("[^"]*"|[^,}\\s]+)`, 'gi');
    out = out.replace(re, `$1"${REDACTED_VALUE}"`);
  }
  return out;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function redactRequest(req: CapturedRequest, cfg: RedactionConfig): CapturedRequest {
  if (!cfg.enabled) return req;
  return {
    ...req,
    requestHeaders: maskHeaders(req.requestHeaders, cfg.headerPatterns),
    requestCookies: req.requestCookies ? maskHeaders(req.requestCookies, cfg.headerPatterns) : undefined,
    responseHeaders: maskHeaders(req.responseHeaders, cfg.headerPatterns),
    responseCookies: req.responseCookies ? maskHeaders(req.responseCookies, cfg.headerPatterns) : undefined,
    requestBody: maskBody(req.requestBody, cfg.bodyPatterns),
    responseBody: maskBody(req.responseBody, cfg.bodyPatterns),
  };
}

export function redactAll(reqs: CapturedRequest[], cfg: RedactionConfig): CapturedRequest[] {
  if (!cfg.enabled) return reqs;
  return reqs.map((r) => redactRequest(r, cfg));
}
