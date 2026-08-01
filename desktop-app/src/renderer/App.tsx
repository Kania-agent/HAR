import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Badge, Group, Text, useMantineColorScheme } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import type {
  CapturedRequest,
  ResourceType,
  WebSocketMessage,
  EventSourceMessage,
  PageEvent,
  RedactionConfig,
  CaptchaDetection,
  CaptureScope,
  Session,
} from '@har-suite/shared';
import { DEFAULT_REDACTION } from '@har-suite/shared';
import NetworkList from './components/NetworkList';
import RequestDetail from './components/RequestDetail';
import Toolbar from './components/Toolbar';
import AllowlistDialog from './components/AllowlistDialog';
import RedactionDialog from './components/RedactionDialog';
import PairingDialog from './components/PairingDialog';
import CaptchasPanel from './components/CaptchasPanel';
import SessionsSidebar from './components/SessionsSidebar';
import NewSessionDialog from './components/NewSessionDialog';
import AppCaptureDialog from './components/AppCaptureDialog';
import CaptureCommandDialog from './components/CaptureCommandDialog';
import AppFilterDialog from './components/AppFilterDialog';
import ContextMenu, { type CtxItem } from './components/ContextMenu';

export type TypeFilter = 'All' | ResourceType;
export type Theme = 'dark' | 'light';

const THEME_KEY = 'har-suite-theme';

export default function App() {
  const [requests, setRequests] = useState<Map<string, CapturedRequest>>(new Map());
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('All');
  const [searchBody, setSearchBody] = useState(false);
  const [allowlist, setAllowlist] = useState<string[]>([]);
  const [capturing, setCapturing] = useState(true);
  const [scope, setScope] = useState<CaptureScope>('data');
  const [connected, setConnected] = useState(false);
  const [token, setToken] = useState('');
  const [redaction, setRedaction] = useState<RedactionConfig>(DEFAULT_REDACTION);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [currentSessionId, setCurrentSessionId] = useState<number | null>(null);

  const [showAllowlist, setShowAllowlist] = useState(false);
  const [showRedaction, setShowRedaction] = useState(false);
  const [showPairing, setShowPairing] = useState(false);
  const [showCaptchas, setShowCaptchas] = useState(false);
  const [showNewSession, setShowNewSession] = useState(false);
  const [showAppCapture, setShowAppCapture] = useState(false);
  const [showCaptureCli, setShowCaptureCli] = useState(false);
  const [captchas, setCaptchas] = useState<Map<string, CaptchaDetection>>(new Map());

  const [appCapturing, setAppCapturing] = useState(false);
  const [appCaptureSupported, setAppCaptureSupported] = useState(true);
  const [cliGlobalActive, setCliGlobalActive] = useState(false);
  const [showAppFilter, setShowAppFilter] = useState(false);
  const [appFilterExeNames, setAppFilterExeNames] = useState<string[]>([]);
  const [appFilterBypass, setAppFilterBypass] = useState(false);

  const [theme, setTheme] = useState<Theme>(
    () => (localStorage.getItem(THEME_KEY) as Theme) || 'dark',
  );
  const { setColorScheme } = useMantineColorScheme();
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number; id: string } | null>(null);

  useEffect(() => {
    // Keep our custom CSS-variable theming (data-theme) and Mantine's color
    // scheme in lockstep from the single toggle.
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
    setColorScheme(theme);
  }, [theme, setColorScheme]);

  const refreshSessions = useCallback(async () => {
    setSessions(await window.harSuite.listSessions());
  }, []);

  // Debounced refresh — call freely as requests stream in; only fires every ~1.5s.
  const sessionRefreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const scheduleSessionRefresh = useCallback(() => {
    if (sessionRefreshTimer.current) return;
    sessionRefreshTimer.current = setTimeout(() => {
      sessionRefreshTimer.current = null;
      refreshSessions();
    }, 1500);
  }, [refreshSessions]);

  useEffect(() => {
    (async () => {
      const all = await window.harSuite.getAll();
      setRequests(new Map(all.map((r) => [r.id, r])));
      const allCaptchas = await window.harSuite.getCaptchas();
      setCaptchas(new Map(allCaptchas.map((c) => [c.id, c])));
      const s = await window.harSuite.getStatus();
      setAllowlist(s.allowlist);
      setCapturing(s.captureEnabled);
      if (s.scope) setScope(s.scope);
      setConnected(s.connected);
      if (s.token) setToken(s.token);
      if (s.redaction) setRedaction(s.redaction);
      setCurrentSessionId(s.sessionId ?? null);
      refreshSessions();
      try {
        const a = await window.harSuite.getAppCaptureStatus();
        setAppCapturing(a.enabled);
        setAppCaptureSupported(a.supported ?? true);
        const c = await window.harSuite.getCliStatus();
        setCliGlobalActive(c.globalEnvActive);
        const af = await window.harSuite.getAppFilter();
        setAppFilterExeNames(af.exeNames);
        setAppFilterBypass(af.bypass);
      } catch {}
    })();

    const offReq = window.harSuite.onRequest((req) => {
      setRequests((prev) => {
        const next = new Map(prev);
        next.set(req.id, req);
        return next;
      });
      scheduleSessionRefresh();
    });
    const offUpd = window.harSuite.onUpdate((id, patch) => {
      setRequests((prev) => {
        const cur = prev.get(id);
        if (!cur) return prev;
        const next = new Map(prev);
        next.set(id, { ...cur, ...patch });
        return next;
      });
    });
    const offWs = window.harSuite.onWsMessage((id, msg: WebSocketMessage) => {
      setRequests((prev) => {
        const cur = prev.get(id);
        if (!cur) return prev;
        const next = new Map(prev);
        next.set(id, { ...cur, wsMessages: [...(cur.wsMessages ?? []), msg] });
        return next;
      });
    });
    const offSse = window.harSuite.onSseMessage?.((id, msg: EventSourceMessage) => {
      setRequests((prev) => {
        const cur = prev.get(id);
        if (!cur) return prev;
        const next = new Map(prev);
        next.set(id, {
          ...cur,
          eventSourceMessages: [...(cur.eventSourceMessages ?? []), msg],
        });
        return next;
      });
    });
    // Page events are not tied to a single request — they provide timeline context.
    // We could store them in a separate state, but for now we just log them.
    // The desktop app already has a timeline view; page events enrich it.
    const offPage = window.harSuite.onPageEvent?.((_tabId: number, _event: PageEvent) => {
      // Page events are broadcast for timeline enrichment; no per-request state update needed.
      // Future: store in a dedicated pageEvents state for timeline markers.
    });
    const offStatus = window.harSuite.onStatus((s) => {
      setAllowlist(s.allowlist);
      setCapturing(s.captureEnabled);
      if (s.scope) setScope(s.scope);
      setConnected(s.connected);
    });
    const offAppStatus = window.harSuite.onAppCaptureStatus((a) => {
      setAppCapturing(a.enabled);
    });
    const offCliStatus = window.harSuite.onCliStatus((c) => {
      setCliGlobalActive(c.globalEnvActive);
    });
    const offConn = window.harSuite.onConnection(async (c) => {
      setConnected(c.connected);
      // On (re)connect, pull fresh status so allowlist/redaction/etc. reflect
      // whatever the extension pushed during the auth handshake.
      if (c.connected) {
        try {
          const s = await window.harSuite.getStatus();
          setAllowlist(s.allowlist);
          setCapturing(s.captureEnabled);
        } catch {}
      }
    });
    const offClear = window.harSuite.onCleared(({ sessionId }) => {
      setRequests(new Map());
      setCaptchas(new Map());
      setSelectedId(null);
      setCurrentSessionId(sessionId);
      refreshSessions();
    });
    const offReload = window.harSuite.onReloaded(
      ({ sessionId, requests: list, captchas: caplist }) => {
        setRequests(new Map(list.map((r) => [r.id, r])));
        setCaptchas(new Map((caplist ?? []).map((c) => [c.id, c])));
        setCurrentSessionId(sessionId);
        setSelectedId(null);
      },
    );
    const offCaptcha = window.harSuite.onCaptcha((det) => {
      setCaptchas((prev) => {
        const next = new Map(prev);
        const existing = next.get(det.id);
        // Keep entry with non-empty sitekey when there's a conflict.
        if (!existing || (!existing.sitekey && det.sitekey)) next.set(det.id, det);
        return next;
      });
      scheduleSessionRefresh();
    });

    return () => {
      offReq();
      offUpd();
      offWs();
      offSse?.();
      offPage?.();
      offStatus();
      offAppStatus();
      offCliStatus();
      offConn();
      offClear();
      offReload();
      offCaptcha();
      if (sessionRefreshTimer.current) {
        clearTimeout(sessionRefreshTimer.current);
        sessionRefreshTimer.current = null;
      }
    };
  }, [refreshSessions, scheduleSessionRefresh]);

  const filtered = useMemo(() => {
    const arr = Array.from(requests.values()).sort((a, b) => a.startedAt - b.startedAt);
    const q = filter.trim().toLowerCase();
    return arr.filter((r) => {
      if (typeFilter !== 'All' && r.type !== typeFilter) return false;
      if (!q) return true;
      if (
        r.url.toLowerCase().includes(q) ||
        r.method.toLowerCase().includes(q) ||
        (r.status ? String(r.status).includes(q) : false)
      )
        return true;
      if (searchBody) {
        if (r.requestBody?.toLowerCase().includes(q)) return true;
        if (r.responseBody?.toLowerCase().includes(q)) return true;
      }
      return false;
    });
  }, [requests, filter, typeFilter, searchBody]);

  const timeRange = useMemo(() => {
    if (filtered.length === 0) return { start: 0, end: 1 };
    let start = Infinity,
      end = 0;
    for (const r of filtered) {
      if (r.startedAt < start) start = r.startedAt;
      const e = r.endedAt ?? r.startedAt + (r.durationMs ?? 0);
      if (e > end) end = e;
    }
    if (start === Infinity) start = 0;
    if (end <= start) end = start + 1;
    return { start, end };
  }, [filtered]);

  const selected = selectedId ? (requests.get(selectedId) ?? null) : null;

  const handleClear = async () => {
    await window.harSuite.clear();
    setRequests(new Map());
    setSelectedId(null);
  };

  const handleExport = async (format: 'har' | 'zip') => {
    const ids = filtered.map((r) => r.id);
    const res = await window.harSuite.exportData(format, ids);
    if (!res.ok && res.error !== 'cancelled')
      notifications.show({
        color: 'red',
        title: 'Export failed',
        message: res.error ?? 'Unknown error',
      });
    else if (res.ok)
      notifications.show({
        color: 'green',
        title: 'Export complete',
        message: `${res.count} request(s) → ${res.path}`,
      });
  };

  const handleImport = async () => {
    const res = await window.harSuite.importHar();
    if (!res.ok && res.error !== 'cancelled')
      notifications.show({
        color: 'red',
        title: 'Import failed',
        message: res.error ?? 'Unknown error',
      });
    else if (res.ok)
      notifications.show({
        color: 'green',
        title: 'Import complete',
        message: `${res.count} request(s)`,
      });
  };

  const toggleCapture = async () => {
    const newVal = !capturing;
    setCapturing(newVal);
    await window.harSuite.setCapture(newVal);
  };

  const changeScope = async (next: CaptureScope) => {
    setScope(next);
    await window.harSuite.setScope(next);
  };

  const toggleAppCapture = () => {
    if (appCapturing) {
      // Disabling is immediate — restores the system proxy.
      window.harSuite.setAppCapture(false).then(() => setAppCapturing(false));
    } else {
      // Enabling shows the first-run explainer (CA + proxy consent).
      setShowAppCapture(true);
    }
  };

  const enableAppCapture = async () => {
    const res = await window.harSuite.setAppCapture(true);
    if (res.ok) {
      setAppCapturing(true);
      setShowAppCapture(false);
      notifications.show({
        color: 'teal',
        title: 'App capture enabled',
        message: 'Native app traffic is now being captured via the local proxy.',
      });
    } else {
      notifications.show({
        color: 'red',
        title: 'Could not enable app capture',
        message: res.error ?? 'Unknown error',
      });
    }
  };

  const setCliGlobal = async (enabled: boolean) => {
    const res = await window.harSuite.setGlobalEnv(enabled);
    if (res.ok) {
      setCliGlobalActive(enabled);
      notifications.show({
        color: enabled ? 'teal' : 'gray',
        title: enabled ? 'Global CLI capture ON' : 'Global CLI capture OFF',
        message: enabled
          ? 'New terminals will route through the capture proxy. Existing terminals are unaffected.'
          : 'Your user environment has been restored.',
      });
    } else {
      notifications.show({
        color: 'red',
        title: 'Could not change global CLI capture',
        message: res.error ?? 'Unknown error',
      });
    }
  };

  const saveAllowlist = async (domains: string[]) => {
    setAllowlist(domains);
    await window.harSuite.setAllowlist(domains);
    setShowAllowlist(false);
  };

  const saveRedaction = async (cfg: RedactionConfig) => {
    setRedaction(cfg);
    await window.harSuite.setRedaction(cfg);
    setShowRedaction(false);
  };

  const saveAppFilter = async (data: { exeNames: string[]; bypass: boolean }) => {
    setAppFilterExeNames(data.exeNames);
    setAppFilterBypass(data.bypass);
    await window.harSuite.setAppFilter(data);
    setShowAppFilter(false);
  };

  const regenerateToken = async () => {
    const t = await window.harSuite.regenerateToken();
    setToken(t);
  };

  // window.prompt() is unsupported in Electron renderers (returns "" and warns),
  // so session creation goes through an in-app modal instead.
  const createSession = async (name: string) => {
    setShowNewSession(false);
    await window.harSuite.newSession(name);
    refreshSessions();
  };
  const openSession = async (id: number) => {
    await window.harSuite.openSession(id);
    refreshSessions();
  };
  const deleteSession = async (id: number) => {
    if (!confirm('Delete this session and all its requests?')) return;
    await window.harSuite.deleteSession(id);
    refreshSessions();
  };
  const renameSessionById = async (id: number, name: string) => {
    await window.harSuite.renameSession(id, name);
    refreshSessions();
  };

  const contextMenuItems = useMemo<CtxItem[]>(() => {
    const id = ctxMenu?.id;
    if (!id) return [];
    return [
      {
        label: 'Copy URL',
        action: async () => {
          await window.harSuite.copyUrl(id);
        },
      },
      {
        label: 'Copy as cURL',
        action: async () => {
          await window.harSuite.toCurl(id);
        },
      },
      {
        label: 'Copy as fetch()',
        action: async () => {
          await window.harSuite.toFetch(id);
        },
      },
      { sep: true },
      {
        label: 'Export this as .har',
        action: async () => {
          const res = await window.harSuite.exportData('har', [id]);
          if (!res.ok && res.error !== 'cancelled')
            notifications.show({ color: 'red', title: 'Export failed', message: res.error ?? '' });
        },
      },
      {
        label: 'Export this as .zip',
        action: async () => {
          const res = await window.harSuite.exportData('zip', [id]);
          if (!res.ok && res.error !== 'cancelled')
            notifications.show({ color: 'red', title: 'Export failed', message: res.error ?? '' });
        },
      },
    ];
  }, [ctxMenu]);

  return (
    <div className="app">
      <Toolbar
        filter={filter}
        onFilterChange={setFilter}
        typeFilter={typeFilter}
        onTypeFilterChange={setTypeFilter}
        searchBody={searchBody}
        onSearchBodyChange={setSearchBody}
        capturing={capturing}
        onToggleCapture={toggleCapture}
        appCapturing={appCapturing}
        onToggleAppCapture={toggleAppCapture}
        appCaptureSupported={appCaptureSupported}
        onCaptureCli={() => setShowCaptureCli(true)}
        cliGlobalActive={cliGlobalActive}
        scope={scope}
        onScopeChange={changeScope}
        onClear={handleClear}
        onExport={handleExport}
        onImport={handleImport}
        onAllowlist={() => setShowAllowlist(true)}
        onRedaction={() => setShowRedaction(true)}
        onPairing={() => setShowPairing(true)}
        onCaptchas={() => setShowCaptchas(true)}
        onAppFilter={() => setShowAppFilter(true)}
        appFilterCount={appFilterExeNames.length}
        captchaCount={captchas.size}
        theme={theme}
        onToggleTheme={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
        total={requests.size}
        filtered={filtered.length}
        redactionActive={redaction.enabled}
      />
      <div className="main">
        <SessionsSidebar
          sessions={sessions}
          currentId={currentSessionId}
          onNew={() => setShowNewSession(true)}
          onOpen={openSession}
          onDelete={deleteSession}
          onRename={renameSessionById}
        />
        <div className="list-pane">
          {filtered.length === 0 ? (
            <div className="empty">
              <Text>No requests yet</Text>
            </div>
          ) : (
            <NetworkList
              items={filtered}
              selectedId={selectedId}
              onSelect={setSelectedId}
              onContextMenu={(e, id) => {
                e.preventDefault();
                setCtxMenu({ x: e.clientX, y: e.clientY, id });
              }}
              timeRange={timeRange}
            />
          )}
        </div>
        <div className="detail-pane">
          {selected ? (
            <RequestDetail request={selected} highlight={filter} />
          ) : (
            <div className="empty">Select a request to inspect</div>
          )}
        </div>
      </div>
      <Group className="statusbar" gap="md" wrap="nowrap">
        <Group gap={6} wrap="nowrap">
          <span className={`dot ${connected ? 'on' : 'off'}`} />
          <Text size="xs" inherit>
            {connected ? 'Extension paired' : 'Waiting for extension'}
          </Text>
        </Group>
        <Text size="xs" inherit>
          Capture: {capturing ? 'ON' : 'OFF'}
        </Text>
        <Text size="xs" inherit title="Capture scope">
          Scope: {scope === 'all' ? 'Everything' : 'Data + nav'}
        </Text>
        {appCapturing && (
          <Badge variant="light" color="teal" size="sm" title="Native app capture proxy is active">
            🖥 Apps :8888
          </Badge>
        )}
        {cliGlobalActive && (
          <Badge
            variant="light"
            color="teal"
            size="sm"
            title="Global CLI capture active — new terminals route through the proxy"
          >
            ⌨ CLI global
          </Badge>
        )}
        <Text size="xs" inherit>
          Allowlist: {allowlist.length} domain(s)
        </Text>
        {captchas.size > 0 && (
          <Badge
            variant="light"
            color="violet"
            size="sm"
            style={{ cursor: 'pointer' }}
            onClick={() => setShowCaptchas(true)}
            title="Click to view detected CAPTCHAs"
          >
            🧩 {captchas.size} CAPTCHA{captchas.size === 1 ? '' : 's'}
          </Badge>
        )}
        {redaction.enabled && (
          <Badge variant="light" color="yellow" size="sm" title="Sensitive data masking enabled">
            🛡 Redaction ON
          </Badge>
        )}
        <Text size="xs" inherit>
          Token:{' '}
          <code
            className="token-pill"
            onClick={() => setShowPairing(true)}
            title="Click to view / regenerate"
          >
            {token ? token.slice(0, 8) + '…' : '(unset)'}
          </code>
        </Text>
        <div style={{ flex: 1 }} />
        <Text size="xs" inherit>
          {filtered.length} / {requests.size} requests
        </Text>
      </Group>
      {showAllowlist && (
        <AllowlistDialog
          initial={allowlist}
          onClose={() => setShowAllowlist(false)}
          onSave={saveAllowlist}
        />
      )}
      {showRedaction && (
        <RedactionDialog
          initial={redaction}
          onClose={() => setShowRedaction(false)}
          onSave={saveRedaction}
        />
      )}
      {showPairing && (
        <PairingDialog
          token={token}
          onClose={() => setShowPairing(false)}
          onRegenerate={regenerateToken}
        />
      )}
      {showCaptchas && (
        <CaptchasPanel
          items={Array.from(captchas.values())}
          onClear={async () => {
            await window.harSuite.clearCaptchas();
            setCaptchas(new Map());
          }}
          onClose={() => setShowCaptchas(false)}
        />
      )}
      {showNewSession && (
        <NewSessionDialog
          defaultName={new Date().toISOString().slice(0, 19).replace('T', ' ')}
          onClose={() => setShowNewSession(false)}
          onCreate={createSession}
        />
      )}
      {showAppCapture && (
        <AppCaptureDialog onClose={() => setShowAppCapture(false)} onEnable={enableAppCapture} />
      )}
      {showCaptureCli && (
        <CaptureCommandDialog
          onClose={() => setShowCaptureCli(false)}
          globalActive={cliGlobalActive}
          onSetGlobal={setCliGlobal}
        />
      )}
      {showAppFilter && (
        <AppFilterDialog
          initial={{ exeNames: appFilterExeNames, bypass: appFilterBypass }}
          onClose={() => setShowAppFilter(false)}
          onSave={saveAppFilter}
        />
      )}
      {ctxMenu && (
        <ContextMenu
          x={ctxMenu.x}
          y={ctxMenu.y}
          items={contextMenuItems}
          onClose={() => setCtxMenu(null)}
        />
      )}
    </div>
  );
}
