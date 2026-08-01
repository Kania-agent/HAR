# HAR Capture Suite

Auto-capture network traffic from Chrome — including requests Chrome DevTools itself misses — view requests live in a desktop app with virtualized timeline, persist sessions to SQLite, and export to **HAR** or **ZIP** — with optional sensitive-data redaction.

Captures across **cross-origin iframes (OOPIFs)** and **workers** via flat CDP sessions, so traffic from embedded captchas, payment iframes (Stripe 3DS), and navigating form-POST signups (which the default DevTools Network view drops) is recorded too.

Two pieces:

- **`extension/`** — Chrome MV3 extension. Uses `chrome.debugger` (CDP) with `Target.setAutoAttach` flat sessions to read Network events from a tab **and all its child frames/workers**. Streams them over a paired local WebSocket.
- **`desktop-app/`** — Electron + React + TypeScript app. Runs a token-authenticated WebSocket server (`127.0.0.1:9876`), persists captures to SQLite, manages sessions, and exports.

## What's captured

- **Capture scope** — _Data + navigations_ (default): XHR, Fetch, WebSocket, **Document** (page loads & form-POST signups), Ping/beacon, EventSource, and other API traffic — excluding static assets. _Everything_: adds images, CSS, fonts, scripts. Toggle in the desktop toolbar or extension popup.
- **OOPIF + worker traffic** — cross-origin iframe and (service/dedicated) worker requests, via recursive flat-session auto-attach. This is what makes captcha endpoints and same-tab third-party flows visible.
- **Flow capture (sticky tabs)** — once a tab starts capturing (allowlist match **or** the popup's _Capture this tab_ button), it keeps capturing across **every navigation in that tab**, including to non-allowlisted domains (e.g. `chatgpt.com → stripe.com` during checkout). Stops when the tab closes, capture is turned off, or you click _Stop capturing this tab_.

## Features

| Capability                           | Notes                                                                                                                                        |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Auto-capture across frames & workers | via `chrome.debugger` CDP flat sessions (`Target.setAutoAttach`)                                                                             |
| Configurable capture scope           | Data + navigations (default) or Everything (incl. static assets)                                                                             |
| Sticky-tab flow capture              | keep capturing across same-tab navigations to any domain                                                                                     |
| Allowlist (with subdomain matching)  | configurable from extension popup and desktop app                                                                                            |
| Token-authenticated bridge           | only paired extensions can stream to the desktop                                                                                             |
| Service-worker keep-alive            | `chrome.alarms` heartbeat every ~25s                                                                                                         |
| Recent-host suggestions              | popup shows recently visited hosts with one-click add                                                                                        |
| Persistent sessions                  | SQLite via `better-sqlite3` (WAL mode)                                                                                                       |
| Virtualized network list             | `@tanstack/react-virtual`, handles 10k+ rows                                                                                                 |
| Inline waterfall                     | per-row offset/duration relative to session                                                                                                  |
| Full-text search                     | URL/method/status, with optional body search                                                                                                 |
| Request detail                       | headers, payload, response (with JSON pretty-print), WebSocket frames with filter                                                            |
| Right-click context menu             | Copy URL · Copy as cURL · Copy as fetch · Export this only                                                                                   |
| Import HAR                           | re-open existing captures                                                                                                                    |
| Export HAR / ZIP                     | ZIP includes per-request JSON, summary, and metadata                                                                                         |
| Sensitive-data redaction             | mask headers (Authorization, Cookie, etc.) and JSON body keys at export                                                                      |
| CAPTCHA detection                    | recognizes sitekey + provider via network URLs, DOM scan, and page-world hooks                                                               |
| Dark / light theme                   | persisted to localStorage                                                                                                                    |
| Vitest unit tests                    | for HAR, redaction, cURL, host matching, resource-type inference, capture scope, process filter, captcha detection, and capture-bugfix seams |
| ESLint + Prettier                    | flat config                                                                                                                                  |
| electron-builder                     | NSIS / DMG / AppImage installer recipes                                                                                                      |

## Prerequisites

- Node.js 20+ (LTS)
- Google Chrome / Chromium / Edge
- Windows / macOS / Linux

## Install

```bash
npm install
```

This installs all workspaces (root, `extension/`, `desktop-app/`, `shared/`).

## Build the Chrome extension

```bash
npm run build:extension
```

Output goes to `extension/dist/`. Then load it in Chrome:

1. Open `chrome://extensions`
2. Enable **Developer mode** (top-right)
3. Click **Load unpacked**
4. Select `extension/dist/`
5. Pin the extension

## Run the desktop app

```bash
npm run dev
```

Electron starts in dev mode (Vite HMR for the renderer). The bridge server starts on `127.0.0.1:9876`.

Production build:

```bash
npm run build:desktop
npm start
```

Distributable installers:

```bash
npm run dist    # full installer for current OS
npm run pack    # unpacked binary, no installer
```

## Pairing (first run)

1. Start the desktop app. The status bar shows a **truncated pairing token** (click it to view full).
2. Click the token → **Copy**.
3. Open the extension popup → **Pairing** tab → paste → **Pair**.
4. The status bar dot turns green: **"Extension paired"**.

The token persists between runs. You can regenerate it at any time.

## Usage

1. Add domains in the extension popup or the desktop app's **Allowlist** dialog.
2. Visit an allowlisted page in Chrome. The extension attaches the Chrome debugger (yellow info bar appears — **leave it open**, closing it detaches the debugger).
3. The desktop app fills with live requests. Click a row to inspect; right-click for actions.
4. **Export HAR** or **Export ZIP** to save the current filter result.

## Sessions

Each desktop-app launch creates a new session by default. Sessions are persisted to SQLite:

- **Sidebar** lists all past sessions with request counts.
- Click a session to load it (current session is closed first).
- **Double-click** a session to rename it inline.
- Right-click a session in the sidebar to delete.
- **New session** button: opens a name dialog and starts fresh without losing previous captures.

SQLite DB location: `<userData>/har-suite/capture.db`.

## Allowlist matching

A tab **starts** capturing when its top-level host equals an allowlisted entry **or** ends with `.<entry>`.

| Allowlist entry   | Matches                                             |
| ----------------- | --------------------------------------------------- |
| `example.com`     | `example.com`, `www.example.com`, `api.example.com` |
| `api.example.com` | `api.example.com`, `v2.api.example.com`             |
| `localhost`       | `localhost` only (no subdomains)                    |

Once a tab has started capturing, **flow capture (sticky tabs)** keeps it recording across every subsequent navigation in that same tab — including to domains not on the allowlist (the root domain, another subdomain, or a third party like a payment provider). This means you do **not** need to pre-add every domain in a multi-step flow. Capture for a sticky tab stops only when the tab closes, capture is turned off, or you click _Stop capturing this tab_ in the popup. You can also start sticky capture on any tab with the popup's **Capture this tab** button, regardless of the allowlist.

## Export formats

- **`.har`** — Standard HAR 1.2. Open in Chrome DevTools (Network → drop file) or any HAR viewer.
- **`.zip`** — Contains:
  - `capture.har` — full HAR
  - `summary.json` — flat list of requests with timing/status
  - `metadata.json` — export timestamp, tool version, redaction flag
  - `requests/` — one JSON file per request with raw captured data (including WebSocket frames, SSE messages)

> **RAR not supported**: pure-JS RAR creation is not freely available. ZIP is recommended; open the ZIP and re-archive with WinRAR if you specifically need RAR.

## Captured fields

Every captured request includes the following fields (all persisted to SQLite and included in HAR/ZIP exports):

**Core fields:** method, URL, host, status, status text, request/response headers, request/response body (base64 for binary), resource type, timing (started, ended, duration), from-cache flag.

**Cookie capture (new):**
- `requestCookies` — structured cookie list parsed from the real `Cookie` header sent over the wire (via `Network.requestWillBeSentExtraInfo`). Previous versions only captured pre-cookie headers.
- `responseCookies` — structured `Set-Cookie` list from the real response headers (via `Network.responseReceivedExtraInfo`). Chrome strips `Set-Cookie` from the standard `responseReceived` event; this restores it.

**Server metadata (new):**
- `remoteAddress` — server IP address (e.g. `104.18.32.47`)
- `remotePort` — server port (e.g. `443`)
- `protocol` — network protocol (e.g. `h2`, `http/1.1`)

**Initiator with stack traces (new):**
- `initiator` — full CDP initiator object with `type`, `url`, `lineNumber`, `columnNumber`, and `stack.callFrames[]` (function name + URL + line + column for each frame). Previous versions only captured `initiator.type` as a string.

**WebSocket capture (enhanced):**
- `wsMessages[]` — sent/received frames with direction, timestamp, opcode, payload, binary flag (unchanged)
- `wsError` — protocol-level error text (via `Network.webSocketFrameError`)
- `wsStatus` / `wsStatusText` — handshake response status code and text (via `Network.webSocketWillSendHandshakeResponse`)
- `wsResponseHeaders` — full handshake response headers

**Server-Sent Events (new):**
- `eventSourceMessages[]` — each SSE message with `eventName`, `eventId`, `data`, and `timestamp` (via `Network.eventSourceMessageReceived`). Bounded to 5000 messages per request (drop-oldest).

**Page lifecycle (new):**
- `pageEvents[]` — navigation, DOMContentLoaded, and Load events with timestamp and URL (via `Page.frameNavigated`, `Page.domContentEventFired`, `Page.loadEventFired`). Provides timeline context for when requests occurred relative to page load phases.

**Cache control (new):**
- Cache is force-disabled during capture (`Network.setCacheDisabled`) so response bodies are always fetched fresh from the network — never served from disk cache where `getResponseBody` would return empty.

## Sensitive-data redaction

Open the **Redaction** dialog from the toolbar to mask values at export time:

- **Header patterns** (substring, case-insensitive): default `authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `proxy-authorization`.
- **Body JSON keys**: default `password`, `secret`, `access_token`, `refresh_token`, `id_token`.

Matched values become `<redacted>` in the exported HAR/ZIP. Captured data in memory and SQLite is unchanged — toggle redaction off and re-export to get the original values back.

## CAPTCHA detection

When an allowlisted page triggers or renders a CAPTCHA, the suite extracts the **provider** and **sitekey** and surfaces them in the **CAPTCHAs** panel (toolbar button + status-bar pill).

Because the extension auto-attaches into **cross-origin iframes**, captcha widgets that render in their own frame (the common case for reCAPTCHA, hCaptcha, Turnstile, Arkose) now have their network requests captured, so the network path below detects them reliably instead of intermittently.

Three detection paths run in parallel:

1. **Network URL parsing** — every captured request URL is matched against known endpoints:
   - reCAPTCHA v2/v3/Enterprise: `www.google.com/recaptcha/api2/*`, `/recaptcha/enterprise/*` (sitekey in `k=`)
   - hCaptcha: `*.hcaptcha.com/getcaptcha/<sitekey>` or `sitekey=`
   - Cloudflare Turnstile: `challenges.cloudflare.com/...?sitekey=`
   - Arkose Labs / FunCaptcha: `*.arkoselabs.com/v2/<PUBLIC_KEY>/...`
   - GeeTest v3 (`gt=...&challenge=...`) and v4 (`captcha_id=...`)
   - DataDome: `captcha-delivery.com`, `datadome.co`
   - AWS WAF Captcha: `*.awswaf.com`

2. **DOM scan** (content script on allowlisted tabs) — looks for `.g-recaptcha[data-sitekey]`, `.h-captcha[data-sitekey]`, `.cf-turnstile[data-sitekey]`, Arkose script tags, and generic `[data-sitekey]`. Re-scans on DOM mutations.

3. **Page-world hook** (injected `<script>`) — wraps `grecaptcha.execute`, `grecaptcha.render`, `grecaptcha.enterprise.*`, `hcaptcha.execute/render`, and `turnstile.render/execute`. Captures the sitekey + `action` (for v3) at call time, even when no obvious DOM marker exists.

Detections are deduplicated by `(type, sitekey, pageHost)` and persisted to SQLite alongside requests. Use **Copy** in the panel to copy a sitekey to the clipboard.

Supported labels in the UI: `reCAPTCHA v2`, `reCAPTCHA v3`, `reCAPTCHA Enterprise`, `hCaptcha`, `Cloudflare Turnstile`, `Arkose Labs / FunCaptcha`, `GeeTest`, `GeeTest v4`, `DataDome`, `AWS WAF Captcha`, `Unknown` (generic `[data-sitekey]` fallback).

## Architecture

```
 ┌────────────────────────┐         ┌────────────────────────────┐
 │ Chrome (MV3 Extension) │  WS +   │  Electron Desktop App      │
 │                        │  auth   │                            │
 │  chrome.debugger ──────┼────────►│  ws://127.0.0.1:9876       │
 │  Network.* events      │ stream  │  + token handshake         │
 │                        │         │                            │
 │  Allowlist gate        │◄────────│  React UI (virtualized)    │
 │  Popup UI + Pairing    │ control │  SQLite session store      │
 │  chrome.alarms ka      │         │  HAR / ZIP exporter        │
 └────────────────────────┘         │  Redaction at export       │
                                    └────────────────────────────┘
```

- Allowlist is the **single source of truth** in extension storage. Desktop app sends `set-allowlist` over the bridge; extension echoes back `allowlist-sync` so both sides stay in sync.
- Captures are written to SQLite in batches (500 ms flush) to avoid disk thrash under burst traffic.
- WebSocket frames are captured live and shown in the **Messages** tab of the request detail.
- The bridge requires `auth` as the first message with the matching token; otherwise the connection is dropped after a 5s grace period.

## Repo layout

```
HAR/
├── desktop-app/                 Electron + React + TypeScript
│   ├── src/
│   │   ├── main/                Main process
│   │   │   ├── index.ts         App entry, IPC, lifecycle
│   │   │   ├── bridge-server.ts WS server with auth handshake
│   │   │   ├── store.ts         SQLite persistence
│   │   │   ├── har.ts           HAR 1.2 builder
│   │   │   ├── export.ts        HAR/ZIP exporters
│   │   │   ├── import.ts        HAR importer
│   │   │   ├── redact.ts        Header/body redaction
│   │   │   └── curl.ts          Copy-as-cURL / fetch helpers
│   │   ├── preload/             Context bridge
│   │   └── renderer/            React UI + components
│   ├── electron.vite.config.ts
│   ├── electron-builder.yml
│   └── package.json
├── extension/                   Chrome MV3 extension (esbuild)
│   ├── src/
│   │   ├── background.ts        Service worker
│   │   ├── debugger.ts          CDP capture
│   │   ├── bridge.ts            WebSocket client (auth + reconnect)
│   │   ├── store.ts             Local storage helpers
│   │   └── popup.ts             Popup logic (tabs: Capture / Recent / Pairing)
│   ├── public/
│   │   ├── manifest.json
│   │   └── popup.html
│   ├── scripts/build.mjs        esbuild bundler
│   └── package.json
├── shared/                      Shared types and constants
│   └── src/index.ts
├── tests/                       Vitest unit tests
│   ├── har.test.ts
│   ├── redact.test.ts
│   ├── curl.test.ts
│   ├── host-match.test.ts
│   └── … (capture-scope, process-filter, captcha-detect, infer-resource-type, and bugfix seam tests)
├── eslint.config.mjs
├── vitest.config.ts
├── .prettierrc.json
└── package.json                 Workspace root
```

## Development

Watch the extension while iterating:

```bash
npm run dev:extension
```

After each rebuild, click **Reload** for the HAR Capture Suite entry on `chrome://extensions`. (Tip: install **Extensions Reloader** and pin its toolbar button for one-click reload.)

Run the renderer with HMR:

```bash
npm run dev
```

Renderer changes hot-reload automatically. Main-process changes require restarting `npm run dev`.

### Code quality

```bash
npm run lint        # ESLint
npm run format      # Prettier --write
npm test            # Vitest run
npm run typecheck   # tsc --noEmit
```

## Caveats

- The `chrome.debugger` API forces a yellow info bar in Chrome ("being debugged"). Closing that bar detaches the debugger and stops capture — keep it open while recording.
- Only one client (DevTools **or** this extension) can attach the debugger to a tab at a time. Close DevTools on tabs you want to capture.
- Response bodies for very large or streamed responses may be unavailable from CDP. The HAR entry will still be present without the body.
- MV3 service workers idle out after ~30 s. We use a `chrome.alarms` heartbeat (every 25 s) and event-driven re-attach to keep capture working, but you may briefly see a "disconnected" status during the wake.

## Changelog

### 0.1.2

Capture reliability fixes.

**Desktop app (native-app / MITM capture)**

- `Clear` now deletes the active session's persisted requests from SQLite (previously they reloaded when the session was reopened).
- Copy as cURL / fetch now applies the same redaction as export when redaction is enabled (secrets no longer copied in cleartext). Copy URL remains raw.
- The global Capture toggle now also gates native-app/CLI (MITM) ingestion — turning capture off stops app traffic too, and the status reflects it.
- Native-app WebSocket traffic through the MITM proxy is now captured (connection row + sent/received frames), matching the browser path.

**Chrome extension (CDP capture)**

- Request and WebSocket durations are now computed from a single monotonic time base — previously every extension-captured entry exported `time: 0` (epoch/monotonic mismatch).
- Fixed a race in debugger `attach()` where two concurrent attach attempts on one navigation could delete a live attachment (hung debugger banner / re-attach loop).
- Long-lived WebSockets: their in-flight entry is exempt from the generic eviction cap (frames no longer silently dropped on busy pages), and per-request `wsMessages` are bounded (`MAX_WS_MESSAGES`).
- Binary/base64 fidelity: responses keep their real content-type with a separate base64 flag, and binary WebSocket frames are marked `encoding: base64` in the HAR (`_webSocketMessages`); legacy captures remain readable.
- Extension manifest version aligned with the app version.

## Roadmap

- [x] Auto-attach on allowlisted tabs
- [x] Capture Fetch / XHR / WebSocket (with frames)
- [x] Live network panel with virtualized list & inline waterfall
- [x] HAR 1.2 export, ZIP bundle export
- [x] HAR import
- [x] Token-paired WebSocket bridge
- [x] Service worker keep-alive
- [x] SQLite persisted sessions
- [x] Right-click: Copy URL / cURL / fetch / Export-this
- [x] Body search, theme toggle, recent-host suggestions
- [x] Sensitive-data redaction at export
- [ ] Replay request (re-send from desktop)
- [ ] Pretty-printers for gRPC-Web / MessagePack
- [ ] Auto-update via electron-updater
