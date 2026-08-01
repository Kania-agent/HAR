import { contextBridge, ipcRenderer } from 'electron';
import type {
  CapturedRequest,
  WebSocketMessage,
  EventSourceMessage,
  PageEvent,
  ConsoleMessage,
  WebVitalMetrics,
  RedactionConfig,
  CaptchaDetection,
  CaptureScope,
  Session,
} from '@har-suite/shared';

type StatusPayload = {
  allowlist: string[];
  captureEnabled: boolean;
  scope?: CaptureScope;
  connected: boolean;
  total?: number;
  token?: string;
  sessionId?: number | null;
  redaction?: RedactionConfig;
  appFilter?: string[];
  appFilterBypass?: boolean;
};

type AppFilterPayload = {
  exeNames: string[];
  bypass: boolean;
  seenExes: string[];
  runningProcesses: string[];
};

type AppCaptureStatus = {
  enabled: boolean;
  port: number;
  proxyActive: boolean;
  caInstalled?: boolean;
  supported?: boolean;
};

type CliStatus = {
  proxyRunning: boolean;
  globalEnvActive: boolean;
  commandRunning: boolean;
  supported?: boolean;
  envPreview?: string;
};

type CommandOutput = {
  stream: 'stdout' | 'stderr' | 'exit' | 'error' | 'start';
  data: string;
};

const api = {
  getAll: (): Promise<CapturedRequest[]> => ipcRenderer.invoke('capture:get-all'),
  clear: (): Promise<boolean> => ipcRenderer.invoke('capture:clear'),
  getStatus: (): Promise<StatusPayload> => ipcRenderer.invoke('capture:get-status'),
  setAllowlist: (domains: string[]): Promise<boolean> =>
    ipcRenderer.invoke('capture:set-allowlist', domains),
  setCapture: (enabled: boolean): Promise<boolean> =>
    ipcRenderer.invoke('capture:set-capture', enabled),
  setScope: (scope: CaptureScope): Promise<boolean> =>
    ipcRenderer.invoke('capture:set-scope', scope),

  setAppCapture: (enabled: boolean): Promise<{ ok: boolean; error?: string }> =>
    ipcRenderer.invoke('capture:set-app-capture', enabled),
  getAppCaptureStatus: (): Promise<AppCaptureStatus> =>
    ipcRenderer.invoke('capture:get-app-capture-status'),

  runCommand: (command: string, cwd?: string): Promise<{ ok: boolean; error?: string }> =>
    ipcRenderer.invoke('capture:run-command', { command, cwd }),
  cancelCommand: (): Promise<boolean> => ipcRenderer.invoke('capture:cancel-command'),
  setGlobalEnv: (enabled: boolean): Promise<{ ok: boolean; error?: string }> =>
    ipcRenderer.invoke('capture:set-global-env', enabled),
  getCliStatus: (): Promise<CliStatus> => ipcRenderer.invoke('capture:get-cli-status'),
  setRedaction: (cfg: RedactionConfig): Promise<boolean> =>
    ipcRenderer.invoke('capture:set-redaction', cfg),
  regenerateToken: (): Promise<string> => ipcRenderer.invoke('capture:regenerate-token'),

  getAppFilter: (): Promise<AppFilterPayload> => ipcRenderer.invoke('capture:get-app-filter'),
  setAppFilter: (data: { exeNames: string[]; bypass: boolean }): Promise<boolean> =>
    ipcRenderer.invoke('capture:set-app-filter', data),

  exportData: (
    format: 'har' | 'zip',
    ids?: string[],
  ): Promise<{ ok: boolean; path?: string; count?: number; error?: string }> =>
    ipcRenderer.invoke('capture:export', { format, ids }),
  importHar: (): Promise<{ ok: boolean; count?: number; error?: string }> =>
    ipcRenderer.invoke('capture:import-har'),

  toCurl: (id: string): Promise<string | null> => ipcRenderer.invoke('capture:to-curl', id),
  toFetch: (id: string): Promise<string | null> => ipcRenderer.invoke('capture:to-fetch', id),
  copyUrl: (id: string): Promise<string | null> => ipcRenderer.invoke('capture:copy-url', id),

  getCaptchas: (): Promise<CaptchaDetection[]> => ipcRenderer.invoke('captchas:get-all'),
  clearCaptchas: (): Promise<boolean> => ipcRenderer.invoke('captchas:clear'),
  copySitekey: (id: string): Promise<string | null> =>
    ipcRenderer.invoke('captchas:copy-sitekey', id),

  listSessions: (): Promise<Session[]> => ipcRenderer.invoke('sessions:list'),
  currentSession: (): Promise<number | null> => ipcRenderer.invoke('sessions:current'),
  newSession: (name?: string): Promise<number> => ipcRenderer.invoke('sessions:new', name),
  openSession: (id: number): Promise<number> => ipcRenderer.invoke('sessions:open', id),
  deleteSession: (id: number): Promise<boolean> => ipcRenderer.invoke('sessions:delete', id),
  renameSession: (id: number, name: string): Promise<boolean> =>
    ipcRenderer.invoke('sessions:rename', id, name),

  onRequest: (cb: (req: CapturedRequest) => void) => {
    const handler = (_: unknown, req: CapturedRequest) => cb(req);
    ipcRenderer.on('capture:request', handler);
    return () => ipcRenderer.off('capture:request', handler);
  },
  onUpdate: (cb: (id: string, patch: Partial<CapturedRequest>) => void) => {
    const handler = (_: unknown, payload: { id: string; patch: Partial<CapturedRequest> }) =>
      cb(payload.id, payload.patch);
    ipcRenderer.on('capture:update', handler);
    return () => ipcRenderer.off('capture:update', handler);
  },
  onWsMessage: (cb: (id: string, msg: WebSocketMessage) => void) => {
    const handler = (_: unknown, payload: { id: string; message: WebSocketMessage }) =>
      cb(payload.id, payload.message);
    ipcRenderer.on('capture:ws-message', handler);
    return () => ipcRenderer.off('capture:ws-message', handler);
  },
  onSseMessage: (cb: (id: string, msg: EventSourceMessage) => void) => {
    const handler = (_: unknown, payload: { id: string; message: EventSourceMessage }) =>
      cb(payload.id, payload.message);
    ipcRenderer.on('capture:sse-message', handler);
    return () => ipcRenderer.off('capture:sse-message', handler);
  },
  onPageEvent: (cb: (tabId: number, event: PageEvent) => void) => {
    const handler = (_: unknown, payload: { tabId: number; event: PageEvent }) =>
      cb(payload.tabId, payload.event);
    ipcRenderer.on('capture:page-event', handler);
    return () => ipcRenderer.off('capture:page-event', handler);
  },
  onConsoleMessage: (cb: (tabId: number, msg: ConsoleMessage) => void) => {
    const handler = (_: unknown, payload: { tabId: number; message: ConsoleMessage }) =>
      cb(payload.tabId, payload.message);
    ipcRenderer.on('capture:console-message', handler);
    return () => ipcRenderer.off('capture:console-message', handler);
  },
  onMetrics: (cb: (tabId: number, metrics: WebVitalMetrics) => void) => {
    const handler = (_: unknown, payload: { tabId: number; metrics: WebVitalMetrics }) =>
      cb(payload.tabId, payload.metrics);
    ipcRenderer.on('capture:metrics', handler);
    return () => ipcRenderer.off('capture:metrics', handler);
  },
  onStatus: (cb: (status: StatusPayload) => void) => {
    const handler = (_: unknown, status: StatusPayload) => cb(status);
    ipcRenderer.on('capture:status', handler);
    return () => ipcRenderer.off('capture:status', handler);
  },
  onAppCaptureStatus: (cb: (status: AppCaptureStatus) => void) => {
    const handler = (_: unknown, status: AppCaptureStatus) => cb(status);
    ipcRenderer.on('capture:app-status', handler);
    return () => ipcRenderer.off('capture:app-status', handler);
  },
  onCliStatus: (cb: (status: CliStatus) => void) => {
    const handler = (_: unknown, status: CliStatus) => cb(status);
    ipcRenderer.on('capture:cli-status', handler);
    return () => ipcRenderer.off('capture:cli-status', handler);
  },
  onCommandOutput: (cb: (out: CommandOutput) => void) => {
    const handler = (_: unknown, out: CommandOutput) => cb(out);
    ipcRenderer.on('capture:command-output', handler);
    return () => ipcRenderer.off('capture:command-output', handler);
  },
  onConnection: (cb: (status: { connected: boolean }) => void) => {
    const handler = (_: unknown, payload: { connected: boolean }) => cb(payload);
    ipcRenderer.on('capture:connection', handler);
    return () => ipcRenderer.off('capture:connection', handler);
  },
  onCleared: (cb: (payload: { sessionId: number | null }) => void) => {
    const handler = (_: unknown, payload: { sessionId: number | null }) => cb(payload);
    ipcRenderer.on('capture:cleared', handler);
    return () => ipcRenderer.off('capture:cleared', handler);
  },
  onReloaded: (
    cb: (payload: {
      sessionId: number;
      requests: CapturedRequest[];
      captchas?: CaptchaDetection[];
    }) => void,
  ) => {
    const handler = (
      _: unknown,
      payload: { sessionId: number; requests: CapturedRequest[]; captchas?: CaptchaDetection[] },
    ) => cb(payload);
    ipcRenderer.on('capture:reloaded', handler);
    return () => ipcRenderer.off('capture:reloaded', handler);
  },
  onCaptcha: (cb: (det: CaptchaDetection) => void) => {
    const handler = (_: unknown, det: CaptchaDetection) => cb(det);
    ipcRenderer.on('capture:captcha', handler);
    return () => ipcRenderer.off('capture:captcha', handler);
  },
  onAppFilterChanged: (cb: (data: { exeNames: string[]; bypass: boolean }) => void) => {
    const handler = (_: unknown, data: { exeNames: string[]; bypass: boolean }) => cb(data);
    ipcRenderer.on('capture:app-filter-changed', handler);
    return () => ipcRenderer.off('capture:app-filter-changed', handler);
  },
};

contextBridge.exposeInMainWorld('harSuite', api);

export type HarSuiteApi = typeof api;
