import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  Ban,
  Bot,
  Crosshair,
  Database,
  Download,
  FileJson,
  LayoutDashboard,
  Pause,
  Play,
  Plus,
  Power,
  RefreshCw,
  Repeat,
  Save,
  ScrollText,
  Send,
  Sparkles,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Users,
} from "lucide-react";
import "./styles.css";

const VIEWS = [
  { group: "Inspect", items: [
    ["Dashboard", LayoutDashboard],
    ["Intercept", Pause],
    ["Traffic", Activity],
    ["Timeline", Activity],
    ["Repeater", Repeat],
    ["WebSockets", Server],
    ["Pentest Toolkit", Crosshair],
    ["AI Copilot", Bot],
    ["Threat Scanner", ShieldAlert],
    ["Certificates", ShieldCheck],
    ["Scopes", Crosshair],
  ] },
  { group: "Operate", items: [
    ["Access Control", Users],
    ["Faults", ShieldAlert],
    ["Host Profiles", Server],
    ["Blocks", Ban],
    ["Deployments", Server],
    ["Cache", Database],
    ["Settings", Settings],
    ["Audit Log", ScrollText],
  ] },
];

const VIEW_SLUGS = {
  Dashboard: "",
  Intercept: "intercept",
  Traffic: "traffic",
  Timeline: "timeline",
  Repeater: "repeater",
  WebSockets: "websockets",
  "Pentest Toolkit": "pentest-toolkit",
  "AI Copilot": "ai-copilot",
  "Threat Scanner": "threat-scanner",
  Certificates: "certificates",
  Scopes: "scopes",
  "Access Control": "access-control",
  Faults: "faults",
  "Host Profiles": "host-profiles",
  Blocks: "blocks",
  Deployments: "deployments",
  Cache: "cache",
  Settings: "settings",
  "Audit Log": "audit-log",
};

const SLUG_VIEWS = Object.fromEntries(Object.entries(VIEW_SLUGS).map(([name, slug]) => [slug, name]));

const METHOD_CLASS = {
  GET: "get",
  POST: "post",
  PUT: "put",
  PATCH: "patch",
  DELETE: "delete",
};

function currentViewFromURL() {
  const params = new URLSearchParams(location.search);
  const queryView = params.get("view");
  if (queryView && SLUG_VIEWS[queryView]) return SLUG_VIEWS[queryView];

  const path = location.pathname.replace(/\/+$/, "");
  const prefix = "/admin";
  if (path === prefix || path === "") return "Dashboard";
  if (path.startsWith(`${prefix}/`)) {
    const slug = decodeURIComponent(path.slice(prefix.length + 1).split("/")[0] || "");
    return SLUG_VIEWS[slug] || "Dashboard";
  }
  return "Dashboard";
}

function adminPathForView(view) {
  const slug = VIEW_SLUGS[view] || "";
  const params = new URLSearchParams(location.search);
  params.delete("view");
  params.delete("token");
  const query = params.toString();
  const path = slug ? `/admin/${slug}` : "/admin/";
  return query ? `${path}?${query}` : path;
}

function stripTokenFromURL() {
  const url = new URL(window.location.href);
  if (!url.searchParams.has("token")) return;
  url.searchParams.delete("token");
  const query = url.searchParams.toString();
  history.replaceState(history.state, "", `${url.pathname}${query ? `?${query}` : ""}${url.hash}`);
}

function getToken() {
  const params = new URLSearchParams(location.search);
  const urlToken = params.get("token") || "";
  const value = urlToken || localStorage.getItem("adminToken") || "";
  if (value) localStorage.setItem("adminToken", value);
  if (urlToken) stripTokenFromURL();
  return value;
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const t = getToken();
  if (t) headers.Authorization = `Bearer ${t}`;
  const res = await fetch(path, { ...options, headers });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    const detail = body.trim();
    throw new Error(detail ? `${res.status} ${res.statusText}: ${detail}` : `${res.status} ${res.statusText}`);
  }
  return res.json();
}

function api(path) {
  return request(path);
}

function post(path) {
  return request(path, { method: "POST" });
}

function postJSON(path, body) {
  return request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function putJSON(path, body) {
  return request(path, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function parseJSONEditorValue(value, fallback = {}) {
  const text = String(value || "").trim();
  if (!text) return fallback;
  return JSON.parse(text);
}

function del(path) {
  return request(path, { method: "DELETE" });
}

function authenticatedHref(path) {
  const url = new URL(path, window.location.origin);
  const token = getToken();
  if (token) url.searchParams.set("token", token);
  return `${url.pathname}${url.search}${url.hash}`;
}

function scopeQuery(scopeID) {
  if (!scopeID || scopeID === "all") return "";
  const params = new URLSearchParams({ scope_id: scopeID });
  return `?${params.toString()}`;
}

function isConcreteScope(scopeID) {
  return scopeID && scopeID !== "all" && scopeID !== "__out_of_scope__";
}

function flowMatchesScope(flow, scopeID) {
  if (!scopeID || scopeID === "all") return true;
  if (scopeID === "__out_of_scope__") return !flow.scope_id;
  return flow.scope_id === scopeID;
}

function flowMatchesSearch(flow, search) {
  const term = search.trim().toLowerCase();
  if (!term) return true;
  return [
    flow.method,
    flow.host,
    flow.url,
    flow.protocol,
    flow.mime_type,
    flow.rule_id,
    flow.status ? String(flow.status) : "",
  ].some((value) => String(value || "").toLowerCase().includes(term));
}

function useAsync(factory, deps) {
  const [state, setState] = useState({ loading: true, data: null, error: null });
  useEffect(() => {
    let cancelled = false;
    setState({ loading: true, data: null, error: null });
    factory()
      .then((data) => !cancelled && setState({ loading: false, data, error: null }))
      .catch((error) => !cancelled && setState({ loading: false, data: null, error }));
    return () => { cancelled = true; };
  }, deps);
  return state;
}

function useAsyncStale(factory, deps, initialData = null, resetKey = "") {
  const [state, setState] = useState({ loading: true, data: initialData, error: null });
  const resetKeyRef = useRef(resetKey);
  useEffect(() => {
    let cancelled = false;
    const shouldReset = resetKeyRef.current !== resetKey;
    resetKeyRef.current = resetKey;
    setState((prev) => shouldReset ? { loading: true, data: initialData, error: null } : { ...prev, loading: true, error: null });
    factory()
      .then((data) => !cancelled && setState({ loading: false, data, error: null }))
      .catch((error) => !cancelled && setState((prev) => ({ ...prev, loading: false, error })));
    return () => { cancelled = true; };
  }, deps);
  return state;
}

function App() {
  const [current, setCurrent] = useState(currentViewFromURL);
  const [refreshKey, setRefreshKey] = useState(0);
  const [status, setStatus] = useState("checking");
  const [confirmed, setConfirmed] = useState(localStorage.getItem("responsibleUseConfirmed") === "true");
  const [scopes, setScopes] = useState([]);
  const [selectedScope, setSelectedScope] = useState(localStorage.getItem("selectedScope") || "all");
  const refresh = () => setRefreshKey((v) => v + 1);

  useEffect(() => {
    const onPopState = () => setCurrent(currentViewFromURL());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    getToken();
    const nextPath = adminPathForView(current);
    const currentPath = `${location.pathname}${location.search}`;
    if (nextPath !== currentPath) {
      history.pushState({ view: current }, "", nextPath);
    }
  }, [current]);

  useEffect(() => {
    let cancelled = false;
    api("/api/scopes")
      .then((data) => !cancelled && setScopes(data || []))
      .catch(() => !cancelled && setScopes([]));
    return () => { cancelled = true; };
  }, [refreshKey]);

  useEffect(() => {
    localStorage.setItem("selectedScope", selectedScope);
  }, [selectedScope]);

  const body = useMemo(() => {
    const props = { refreshKey, refresh, setCurrent, selectedScope, scopes };
    switch (current) {
      case "Intercept": return <InterceptView {...props} />;
      case "Traffic": return <TrafficView {...props} />;
      case "Timeline": return <TimelineView {...props} />;
      case "Repeater": return <RepeaterView {...props} />;
      case "WebSockets": return <WebSocketsView {...props} />;
      case "Pentest Toolkit": return <PentestToolkitView {...props} />;
      case "AI Copilot": return <AICopilotView {...props} />;
      case "Threat Scanner": return <ThreatScannerView {...props} />;
      case "Certificates": return <CertificatesView {...props} />;
      case "Scopes": return <ScopesView {...props} setSelectedScope={setSelectedScope} />;
      case "Access Control": return <AccessControlView {...props} />;
      case "Faults": return <FaultsView {...props} />;
      case "Host Profiles": return <HostProfilesView {...props} />;
      case "Blocks": return <BlocksView {...props} />;
      case "Deployments": return <DeploymentsView {...props} />;
      case "Cache": return <CacheView {...props} />;
      case "Settings": return <SettingsView {...props} />;
      case "Audit Log": return <AuditLogView {...props} />;
      default: return <DashboardView refreshKey={refreshKey} setStatus={setStatus} setCurrent={setCurrent} />;
    }
  }, [current, refreshKey, selectedScope, scopes]);

  return (
    <>
      <header className="topbar">
        <div className="brand"><img className="brand-mark" src="./logo-mark.svg" alt="" aria-hidden="true" />MITM Proxy Admin</div>
        <span className="env-pill">research console</span>
        <label className="scope-select">Scope
          <select value={selectedScope} onChange={(e) => setSelectedScope(e.target.value)}>
            <option value="all">All traffic</option>
            <option value="__out_of_scope__">Out of scope</option>
            {scopes.filter((scope) => scope.enabled).map((scope) => <option key={scope.id} value={scope.id}>{scope.name}</option>)}
          </select>
        </label>
        <span id="status" className="status-pill">{status}</span>
      </header>
      <main className="shell">
        <nav className="sidebar">
          {VIEWS.map((group) => (
            <div key={group.group}>
              <div className="navgroup">{group.group}</div>
              {group.items.map(([name, Icon]) => (
                <button key={name} className={name === current ? "active" : ""} onClick={() => setCurrent(name)}>
                  <Icon aria-hidden="true" />
                  <span>{name}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>
        <section className="page">{body}</section>
      </main>
      {!confirmed && (
        <div className="modal-backdrop">
          <div className="modal" role="dialog" aria-modal="true" aria-labelledby="consent-title">
            <h2 id="consent-title">Responsible use confirmation</h2>
            <p>I confirm this proxy will only be used on systems and networks I am authorised to inspect.</p>
            <button className="primary" onClick={() => {
              localStorage.setItem("responsibleUseConfirmed", "true");
              setConfirmed(true);
            }}>Confirm</button>
          </div>
        </div>
      )}
    </>
  );
}

function PageState({ state }) {
  if (state.loading) return <div className="panel muted">Loading...</div>;
  if (state.error) return <div className="panel error">Unable to load: <code>{state.error.message || String(state.error)}</code></div>;
  return null;
}

function DashboardView({ refreshKey, setStatus, setCurrent }) {
  const [restartState, setRestartState] = useState({ status: "idle", message: "" });
  const [liveKey, setLiveKey] = useState(0);
  const liveTimerRef = useRef(null);
  const state = useAsync(async () => {
    const [health, version, trafficStats, recentTraffic, audit, threats, cache, timeline] = await Promise.all([
      api("/api/health"),
      api("/api/version"),
      api("/api/traffic/stats"),
      api("/api/traffic?limit=40"),
      api("/api/audit"),
      api("/api/threats/events"),
      api("/api/cache?limit=1"),
      api("/api/timeline?limit=40"),
    ]);
    return { health, version, trafficStats, recentTraffic, audit, threats, cache, timeline };
  }, [refreshKey, liveKey]);

  useEffect(() => {
    const source = new EventSource(`/api/traffic/stream?token=${encodeURIComponent(getToken())}`);
    const scheduleRefresh = () => {
      if (liveTimerRef.current) return;
      liveTimerRef.current = setTimeout(() => {
        liveTimerRef.current = null;
        setLiveKey((value) => value + 1);
      }, 650);
    };
    [
      "traffic.request.started",
      "traffic.response.completed",
      "traffic.tunnel.opened",
      "traffic.blocked",
      "cache.hit",
      "cache.miss",
      "fault.injected",
      "intercept.pending",
      "intercept.resolved",
      "websocket.connection",
      "websocket.frame",
      "config.updated",
      "host_profile.matched",
    ].forEach((topic) => source.addEventListener(topic, scheduleRefresh));
    source.onerror = () => source.close();
    return () => {
      source.close();
      if (liveTimerRef.current) {
        clearTimeout(liveTimerRef.current);
        liveTimerRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    if (state.data?.health?.status) setStatus(state.data.health.status);
  }, [state.data, setStatus]);

  if (state.loading || state.error) return <PageState state={state} />;
  const { health, version, trafficStats, recentTraffic, audit, threats, cache, timeline } = state.data;
  const totalTraffic = Number(trafficStats.total || 0);
  const cacheHits = Number(trafficStats.cache_hit || cache?.hits || 0);
  const blockedTraffic = Number(trafficStats.blocked || threats.metrics?.blocked_threats || 0);
  const recentFlows = recentTraffic || [];
  const timelineEntries = timeline || [];
  const recentStatusBuckets = statusBuckets(recentFlows);
  const methodBuckets = methodBucketsFromFlows(recentFlows);
  const timelineBuckets = timelineKindBuckets(timelineEntries);
  const latencySeries = recentFlows.slice().reverse().map((flow) => Number(flow.duration_ms || 0)).filter((value) => value >= 0);
  const uptime = formatDuration(Number(health.uptime_seconds || 0));
  const reloadConfig = async () => {
    await post("/api/deployments/current/reload");
    location.reload();
  };
  const restartProxy = async () => {
    setRestartState({ status: "pending", message: "Restart requested. Waiting for the process to respond..." });
    try {
      await post("/api/deployments/current/restart");
      setRestartState({ status: "success", message: "Restart requested successfully." });
    } catch (error) {
      setRestartState({ status: "error", message: error.message });
    }
  };
  return (
    <div className="page-stack">
      <PageTitle
        title="Dashboard"
        subtitle={`Proxy control plane - last sync ${new Date(health.time).toLocaleTimeString()}`}
        actions={(
          <>
            <button className="secondary" onClick={reloadConfig}><RefreshCw />Reload config</button>
            <button className="primary" onClick={restartProxy}><Power />Restart proxy</button>
          </>
        )}
      />
      <div className="grid metrics-grid">
        <Metric label="Proxy" value={health.proxy.listen_addr} />
        <Metric label="MITM" value={health.proxy.mitm_enabled ? "enabled" : "disabled"} tone={health.proxy.mitm_enabled ? "success" : ""} />
        <Metric label="Admin" value={health.admin.addr} />
        <Metric label="Version" value={version.version} />
      </div>
      <div className="grid metrics-grid">
        <Metric label="Requests captured" value={totalTraffic} />
        <Metric label="Threats blocked" value={blockedTraffic} />
        <Metric label="Cache hit rate" value={`${cacheHits} / ${totalTraffic}`} />
        <Metric label="Uptime" value={uptime} hint="hh:mm" />
      </div>
      <div className="dashboard-charts">
        <ChartPanel title="Traffic Mix" subtitle="Recent HTTP statuses">
          <DonutChart segments={recentStatusBuckets} centerLabel={`${recentFlows.length}`} centerSub="recent" />
        </ChartPanel>
        <ChartPanel title="Methods" subtitle="Recent request methods">
          <BarList data={methodBuckets} />
        </ChartPanel>
        <ChartPanel title="Timeline Events" subtitle="Last 40 persisted events">
          <BarList data={timelineBuckets} />
        </ChartPanel>
        <ChartPanel title="Latency" subtitle="Recent response durations">
          <Sparkline values={latencySeries} />
        </ChartPanel>
      </div>
      {restartState.message && <div className={`restart-feedback ${restartState.status}`}>{restartState.message}</div>}
      <div className="dashboard-panels">
        <SummaryPanel title="Recent traffic" action={<button className="rowbutton" onClick={() => setCurrent("Traffic")}>View all</button>}>
          <TrafficSummaryList flows={recentFlows.slice(0, 5)} />
        </SummaryPanel>
        <SummaryPanel title="Audit log" action={<button className="rowbutton" onClick={() => setCurrent("Audit Log")}>Open</button>}>
          <AuditSummaryList entries={(audit || []).slice(0, 4)} />
        </SummaryPanel>
      </div>
    </div>
  );
}

function SummaryPanel({ title, action, children }) {
  return (
    <div className="panel summary-panel">
      <div className="summary-head">
        <h2>{title}</h2>
        {action}
      </div>
      {children}
    </div>
  );
}

function TrafficSummaryList({ flows }) {
  if (!flows.length) return <div className="empty-list">No traffic captured yet.</div>;
  return (
    <div className="summary-list">
      {flows.map((flow) => (
        <div className="summary-row traffic-summary-row" key={flow.id}>
          <MethodPill method={flow.method || "REQ"} />
          <div className="summary-main">
            <strong>{flow.host || "(unknown host)"}</strong>
            <span>{flow.url || flow.id}</span>
          </div>
          <span className={`status-code ${statusCodeClass(flow.status)}`}>{flow.status || "..."}</span>
        </div>
      ))}
    </div>
  );
}

function AuditSummaryList({ entries }) {
  if (!entries.length) return <div className="empty-list">No audit events recorded yet.</div>;
  return (
    <table className="summary-table">
      <thead><tr><th>Time</th><th>Actor</th><th>Action</th></tr></thead>
      <tbody>
        {entries.map((entry, index) => (
          <tr key={`${entry.created_at}-${entry.action}-${index}`}>
            <td>{timeOnly(entry.created_at)}</td>
            <td><span className={`scope-badge ${entry.actor === "system" ? "" : "out"}`}>{entry.actor || "admin"}</span></td>
            <td><code>{entry.action}</code></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ChartPanel({ title, subtitle, children }) {
  return (
    <div className="panel chart-panel">
      <div className="chart-head">
        <h2>{title}</h2>
        <span>{subtitle}</span>
      </div>
      {children}
    </div>
  );
}

function DonutChart({ segments, centerLabel, centerSub }) {
  const total = segments.reduce((sum, item) => sum + item.value, 0);
  let offset = 0;
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  return (
    <div className="donut-wrap">
      <svg className="donut-chart" viewBox="0 0 120 120" role="img" aria-label="Traffic mix chart">
        <circle className="donut-track" cx="60" cy="60" r={radius} />
        {total > 0 && segments.map((segment) => {
          const length = (segment.value / total) * circumference;
          const currentOffset = offset;
          offset += length;
          return <circle key={segment.label} className={`donut-segment ${segment.tone || ""}`} cx="60" cy="60" r={radius} strokeDasharray={`${length} ${circumference - length}`} strokeDashoffset={-currentOffset} />;
        })}
        <text x="60" y="57" textAnchor="middle" className="donut-center">{centerLabel}</text>
        <text x="60" y="73" textAnchor="middle" className="donut-sub">{centerSub}</text>
      </svg>
      <div className="chart-legend">
        {segments.map((segment) => <div key={segment.label}><span className={`legend-dot ${segment.tone || ""}`} />{segment.label}<strong>{segment.value}</strong></div>)}
      </div>
    </div>
  );
}

function BarList({ data }) {
  const max = Math.max(1, ...data.map((item) => item.value));
  if (!data.length) return <div className="empty-list">No data yet.</div>;
  return (
    <div className="bar-list">
      {data.map((item) => (
        <div className="bar-row" key={item.label}>
          <div className="bar-label"><span>{item.label}</span><strong>{item.value}</strong></div>
          <div className="bar-track"><div className={`bar-fill ${item.tone || ""}`} style={{ width: `${Math.max(6, (item.value / max) * 100)}%` }} /></div>
        </div>
      ))}
    </div>
  );
}

function Sparkline({ values }) {
  const width = 280;
  const height = 104;
  const clean = values.length ? values : [0];
  const max = Math.max(1, ...clean);
  const points = clean.map((value, index) => {
    const x = clean.length === 1 ? width / 2 : (index / (clean.length - 1)) * width;
    const y = height - (value / max) * (height - 18) - 9;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const latest = values.length ? values[values.length - 1] : 0;
  return (
    <div className="sparkline-wrap">
      <svg className="sparkline" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="Latency sparkline">
        <polyline points={points} />
      </svg>
      <div className="sparkline-meta"><strong>{latest} ms</strong><span>latest</span><span>max {Math.max(0, ...values)} ms</span></div>
    </div>
  );
}

function statusBuckets(flows) {
  const buckets = [
    { label: "2xx", value: 0, tone: "ok" },
    { label: "3xx", value: 0, tone: "info" },
    { label: "4xx", value: 0, tone: "warn" },
    { label: "5xx", value: 0, tone: "danger" },
    { label: "Other", value: 0, tone: "" },
  ];
  for (const flow of flows || []) {
    const status = Number(flow.status || 0);
    if (status >= 200 && status < 300) buckets[0].value += 1;
    else if (status >= 300 && status < 400) buckets[1].value += 1;
    else if (status >= 400 && status < 500) buckets[2].value += 1;
    else if (status >= 500) buckets[3].value += 1;
    else buckets[4].value += 1;
  }
  return buckets.filter((bucket) => bucket.value > 0);
}

function methodBucketsFromFlows(flows) {
  const counts = new Map();
  for (const flow of flows || []) {
    const method = String(flow.method || "REQ").toUpperCase();
    counts.set(method, (counts.get(method) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([label, value]) => ({ label, value, tone: METHOD_CLASS[label] || "" }));
}

function timelineKindBuckets(entries) {
  const counts = new Map();
  for (const entry of entries || []) {
    const kind = String(entry.kind || "event");
    counts.set(kind, (counts.get(kind) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([label, value]) => ({ label, value, tone: label }));
}

function statusCodeClass(status) {
  const code = Number(status || 0);
  if (code >= 200 && code < 300) return "ok";
  if (code >= 300 && code < 400) return "redirect";
  if (code >= 400) return "error";
  return "";
}

function timeOnly(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value).slice(11, 19) || String(value);
  return date.toLocaleTimeString([], { hour12: false });
}

function formatDuration(totalSeconds) {
  const safe = Math.max(0, Math.floor(totalSeconds || 0));
  const hours = Math.floor(safe / 3600);
  const minutes = Math.floor((safe % 3600) / 60);
  return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
}

function interceptStateLabel(state) {
  return String(state || "pending").replace(/_/g, " ");
}

function interceptStateClass(state) {
  switch (state) {
    case "pending": return "warn";
    case "forwarded": return "allow";
    case "dropped": return "block";
    case "timed_out": return "timeout";
    default: return "";
  }
}

function normalizeWebSocketFrame(frame) {
  if (!frame || !frame.connection_id) return null;
  return {
    ...frame,
    id: frame.id || `${frame.connection_id}-${frame.created_at || Date.now()}-${frame.direction || ""}-${frame.payload_bytes || 0}`,
    opcode_name: frame.opcode_name || String(frame.opcode || ""),
    payload: frame.payload || "",
    payload_bytes: frame.payload_bytes ?? frame.bytes ?? 0,
  };
}

function frameMatchesSearch(frame, search) {
  const term = search.trim().toLowerCase();
  if (!term) return true;
  return [frame.payload, frame.opcode_name, frame.direction].some((value) => String(value || "").toLowerCase().includes(term));
}

function mergeWebSocketFrames(...groups) {
  const seen = new Set();
  return groups.flat().filter(Boolean).filter((frame) => {
    if (seen.has(frame.id)) return false;
    seen.add(frame.id);
    return true;
  }).sort((a, b) => {
    const byTime = new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime();
    if (byTime) return byTime;
    return String(b.id || "").localeCompare(String(a.id || ""));
  });
}

function InterceptView({ refreshKey, refresh }) {
  const state = useAsync(async () => {
    const [rules, pending, settings] = await Promise.all([
      api("/api/intercept/rules"),
      api("/api/intercept/pending?limit=100"),
      api("/api/settings"),
    ]);
    return { rules, pending, settings };
  }, [refreshKey]);
  const emptyRule = { name: "", enabled: true, priority: 100, direction: "request", host_patterns: [], method_patterns: [], status_patterns: [], scope_ids: [], content_type_patterns: [] };
  const [selectedRuleID, setSelectedRuleID] = useState(sessionStorage.getItem("selectedInterceptRule") || "");
  const [ruleForm, setRuleForm] = useState(emptyRule);
  const [selectedPendingID, setSelectedPendingID] = useState("");
  const [messageText, setMessageText] = useState("");
  const [actionError, setActionError] = useState("");

  useEffect(() => {
    const source = new EventSource(`/api/traffic/stream?token=${encodeURIComponent(getToken())}`);
    const reload = () => refresh();
    source.addEventListener("intercept.pending", reload);
    source.addEventListener("intercept.resolved", reload);
    return () => source.close();
  }, []);

  useEffect(() => {
    const rule = (state.data?.rules || []).find((item) => item.id === selectedRuleID);
    if (rule) setRuleForm(rule);
  }, [selectedRuleID, state.data]);

  const selectedPending = (state.data?.pending || []).find((item) => item.id === selectedPendingID) || (state.data?.pending || [])[0];
  useEffect(() => {
    if (selectedPending) setMessageText(JSON.stringify(selectedPending.edited || selectedPending.original || {}, null, 2));
  }, [selectedPending?.id]);

  if (state.loading || state.error) return <PageState state={state} />;
  const rules = Array.isArray(state.data?.rules) ? state.data.rules : [];
  const pending = Array.isArray(state.data?.pending) ? state.data.pending : [];
  const interceptSettings = state.data?.settings?.intercept || {};
  const setInterceptEnabled = async (enabled) => {
    await putJSON("/api/settings", {
      intercept: {
        ...interceptSettings,
        enabled,
      },
    });
    refresh();
  };
  const saveRule = async () => {
    if (selectedRuleID) await putJSON(`/api/intercept/rules/${encodeURIComponent(selectedRuleID)}`, ruleForm);
    else {
      const created = await postJSON("/api/intercept/rules", ruleForm);
      sessionStorage.setItem("selectedInterceptRule", created.id);
      setSelectedRuleID(created.id);
    }
    refresh();
  };
  const forward = async () => {
    if (!selectedPending) return;
    setActionError("");
    try {
      await postJSON(`/api/intercept/pending/${encodeURIComponent(selectedPending.id)}/forward`, parseJSONEditorValue(messageText, {}));
      refresh();
    } catch (err) {
      setActionError(err.message);
    }
  };
  const dropPending = async () => {
    if (!selectedPending) return;
    await post(`/api/intercept/pending/${encodeURIComponent(selectedPending.id)}/drop`);
    refresh();
  };
  const replayPending = async () => {
    if (!selectedPending) return;
    const created = await post(`/api/intercept/pending/${encodeURIComponent(selectedPending.id)}/replay`);
    sessionStorage.setItem("selectedRepeaterCase", created.id);
    refresh();
  };
  return (
    <div className="workbench">
      <aside className="workbench-sidebar">
        <div className="workbench-head">
          <div><h2>Intercept</h2><p>Breakpoint rules and paused HTTP messages.</p></div>
          <button className="secondary" onClick={() => { sessionStorage.removeItem("selectedInterceptRule"); setSelectedRuleID(""); setRuleForm(emptyRule); }}><Plus />New Rule</button>
        </div>
        <div className="workbench-list">
          {rules.length ? rules.map((rule) => (
            <button key={rule.id} className={`list-row ${rule.id === selectedRuleID ? "active" : ""}`} onClick={() => { sessionStorage.setItem("selectedInterceptRule", rule.id); setSelectedRuleID(rule.id); }}>
              <div className="list-row-title"><span className={`badge ${rule.direction}`}>{rule.direction}</span><span>{rule.name}</span></div>
              <div className="list-row-meta">priority {rule.priority} - {rule.enabled ? "enabled" : "disabled"}</div>
            </button>
          )) : <EmptyList>No breakpoint rules yet.</EmptyList>}
        </div>
      </aside>
      <section className="workbench-main">
        <div className="detail-shell">
          <div className="detail-topbar">
            <div>
              <h2>Breakpoint Engine</h2>
              <p className="muted">Rules only pause traffic while breakpoints are enabled.</p>
            </div>
            <label className="toggle-row"><input type="checkbox" checked={!!interceptSettings.enabled} onChange={(e) => setInterceptEnabled(e.target.checked)} /> Enable breakpoints</label>
          </div>
          <div className="grid metrics-grid compact">
            <Metric label="State" value={interceptSettings.enabled ? "enabled" : "disabled"} tone={interceptSettings.enabled ? "success" : ""} />
            <Metric label="Timeout" value={`${interceptSettings.timeout_ms || 30000} ms`} />
            <Metric label="Timeout action" value={interceptSettings.timeout_action || "forward"} />
          </div>
        </div>
        <div className="detail-shell">
          <div className="detail-topbar"><div className="detail-title"><h2>{selectedRuleID ? "Edit Rule" : "New Rule"}</h2></div><div className="detail-actions"><button className="primary" onClick={saveRule}><Save />Save</button>{selectedRuleID && <button className="secondary danger-button" onClick={async () => { await del(`/api/intercept/rules/${encodeURIComponent(selectedRuleID)}`); sessionStorage.removeItem("selectedInterceptRule"); setSelectedRuleID(""); setRuleForm(emptyRule); refresh(); }}><Trash2 />Delete</button>}</div></div>
          <div className="settings-grid">
            <label>Name<input value={ruleForm.name || ""} onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })} /></label>
            <label>Priority<input type="number" value={ruleForm.priority || 100} onChange={(e) => setRuleForm({ ...ruleForm, priority: Number(e.target.value) })} /></label>
            <label>Direction<select value={ruleForm.direction || "request"} onChange={(e) => setRuleForm({ ...ruleForm, direction: e.target.value })}><option value="request">request</option><option value="response">response</option></select></label>
            <label><input type="checkbox" checked={ruleForm.enabled !== false} onChange={(e) => setRuleForm({ ...ruleForm, enabled: e.target.checked })} /> Enabled</label>
          </div>
          <div className="split-grid">
            <PatternEditor title="Hosts" placeholder={"example.com\n*.example.com"} values={ruleForm.host_patterns || []} onChange={(values) => setRuleForm({ ...ruleForm, host_patterns: values })} />
            <PatternEditor title="Methods" placeholder={"GET\nPOST"} values={ruleForm.method_patterns || []} onChange={(values) => setRuleForm({ ...ruleForm, method_patterns: values })} />
            <PatternEditor title="Statuses" placeholder={"200\n>=400"} values={ruleForm.status_patterns || []} onChange={(values) => setRuleForm({ ...ruleForm, status_patterns: values })} />
            <PatternEditor title="Content Types" placeholder={"application/json\ntext/html"} values={ruleForm.content_type_patterns || []} onChange={(values) => setRuleForm({ ...ruleForm, content_type_patterns: values })} />
          </div>
        </div>
        <div className="detail-shell">
          <div className="detail-topbar"><div><h2>Paused Messages</h2><p className="muted">{pending.length} recent intercepts.</p></div></div>
          <div className="split-grid">
            <div className="section-card"><h3>Queue</h3><table className="intercept-queue-table"><tbody>{pending.length ? pending.map((item) => <tr key={item.id} className={selectedPending?.id === item.id ? "selected-row" : ""} onClick={() => setSelectedPendingID(item.id)}><td><span className={`badge intercept-state ${interceptStateClass(item.state)}`}>{interceptStateLabel(item.state)}</span></td><td>{item.direction}</td><td><span className="method-pill small">{item.original?.method || item.original?.status}</span></td><td title={item.original?.host || ""}>{item.original?.host}</td></tr>) : <tr><td>No paused messages.</td></tr>}</tbody></table></div>
            <div className="section-card">{selectedPending ? <><JsonEditor title="Editable Message" value={messageText} onChange={setMessageText} minHeight={280} /><div className="actions"><button className="primary" disabled={selectedPending.state !== "pending"} onClick={forward}><Play />Forward</button><button className="secondary danger-button" disabled={selectedPending.state !== "pending"} onClick={dropPending}><Trash2 />Drop</button><button className="secondary" onClick={replayPending}><Repeat />Replay</button></div>{actionError && <p className="error-text">{actionError}</p>}</> : <p className="muted">Select a message.</p>}</div>
          </div>
        </div>
      </section>
    </div>
  );
}

function WebSocketsView({ refreshKey, refresh }) {
  const framePageSize = 20;
  const [selected, setSelected] = useState("");
  const [search, setSearch] = useState("");
  const [connectionsLive, setConnectionsLive] = useState(false);
  const [framesLive, setFramesLive] = useState(false);
  const [connectionsRefreshKey, setConnectionsRefreshKey] = useState(0);
  const [frameLimit, setFrameLimit] = useState(framePageSize);
  const [streamedFrames, setStreamedFrames] = useState([]);
  const connectionsTimerRef = useRef(null);
  const framesTimerRef = useRef(null);
  const frameBufferRef = useRef([]);
  const [sendForm, setSendForm] = useState({ direction: "client_to_server", opcode: 1, payload: "" });
  const state = useAsyncStale(() => api("/api/websockets/connections?limit=100"), [refreshKey, connectionsRefreshKey], [], "connections");
  const framesState = useAsyncStale(async () => selected ? api(`/api/websockets/connections/${encodeURIComponent(selected)}/frames?limit=${frameLimit + 1}&offset=0&q=${encodeURIComponent(search)}`) : [], [selected, search, frameLimit, refreshKey], [], `${selected}\n${search}`);

  useEffect(() => {
    if (!connectionsLive) return undefined;
    const source = new EventSource(`/api/traffic/stream?token=${encodeURIComponent(getToken())}`);
    const scheduleRefresh = () => {
      if (connectionsTimerRef.current) return;
      connectionsTimerRef.current = setTimeout(() => {
        connectionsTimerRef.current = null;
        setConnectionsRefreshKey((value) => value + 1);
      }, 500);
    };
    source.addEventListener("websocket.connection", scheduleRefresh);
    source.addEventListener("websocket.frame", scheduleRefresh);
    source.onerror = () => {
      source.close();
      setConnectionsLive(false);
    };
    return () => {
      source.close();
      if (connectionsTimerRef.current) {
        clearTimeout(connectionsTimerRef.current);
        connectionsTimerRef.current = null;
      }
    };
  }, [connectionsLive]);

  useEffect(() => {
    if (!framesLive || !selected) return undefined;
    const source = new EventSource(`/api/traffic/stream?token=${encodeURIComponent(getToken())}`);
    const scheduleRefresh = (event) => {
      let frame = null;
      try {
        const payload = JSON.parse(event.data || "{}").payload || {};
        frame = normalizeWebSocketFrame(payload.frame || payload);
        if (!frame || frame.connection_id !== selected || !frameMatchesSearch(frame, search)) return;
      } catch {
        return;
      }
      frameBufferRef.current = mergeWebSocketFrames([frame], frameBufferRef.current);
      if (framesTimerRef.current) return;
      framesTimerRef.current = setTimeout(() => {
        framesTimerRef.current = null;
        const batch = frameBufferRef.current;
        frameBufferRef.current = [];
        setStreamedFrames((current) => mergeWebSocketFrames(batch, current).slice(0, frameLimit + 1));
      }, 100);
    };
    source.addEventListener("websocket.frame", scheduleRefresh);
    source.onerror = () => {
      source.close();
      setFramesLive(false);
    };
    return () => {
      source.close();
      if (framesTimerRef.current) {
        clearTimeout(framesTimerRef.current);
        framesTimerRef.current = null;
      }
      frameBufferRef.current = [];
    };
  }, [framesLive, selected, search, frameLimit]);

  useEffect(() => {
    const conns = state.data || [];
    if (!selected && conns.length) setSelected(conns[0].id);
  }, [state.data, selected]);
  useEffect(() => {
    setFrameLimit(framePageSize);
    setStreamedFrames([]);
  }, [selected, search]);
  if ((state.loading || state.error) && !Array.isArray(state.data)) return <PageState state={state} />;
  const conns = Array.isArray(state.data) ? state.data : [];
  const active = conns.find((item) => item.id === selected);
  const fetchedFrames = Array.isArray(framesState.data) ? framesState.data : [];
  const allFrames = mergeWebSocketFrames(streamedFrames, fetchedFrames);
  const frames = allFrames.slice(0, frameLimit);
  const framesHasMore = allFrames.length > frameLimit || fetchedFrames.length > frameLimit;
  const sendFrame = async () => {
    await postJSON(`/api/websockets/connections/${encodeURIComponent(selected)}/send`, { ...sendForm, opcode: Number(sendForm.opcode) });
    setSendForm({ ...sendForm, payload: "" });
    refresh();
  };
  return (
    <div className="workbench">
      <aside className="workbench-sidebar">
        <div className="workbench-head">
          <div className="workbench-head-row">
            <div><h2>WebSockets</h2><p>Captured connections and frames.</p></div>
            <div className="actions">
              <button className={connectionsLive ? "primary" : "secondary"} title={connectionsLive ? "Pause real-time connection list updates" : "Enable real-time connection list updates"} onClick={() => setConnectionsLive((value) => !value)}>
                {connectionsLive ? <Pause /> : <Play />}{connectionsLive ? "Pause" : "Live"}
              </button>
            </div>
          </div>
        </div>
        <div className="workbench-list">{conns.length ? conns.map((conn) => <button key={conn.id} className={`list-row ${conn.id === selected ? "active" : ""}`} onClick={() => setSelected(conn.id)}><div className="list-row-title"><Server /><span>{conn.host}</span></div><div className="list-row-meta">{conn.protocol} - {conn.frame_count || 0} frames</div><div className="list-row-meta">{conn.url}</div></button>) : <EmptyList>No WebSocket connections captured yet.</EmptyList>}</div>
      </aside>
      <section className="workbench-main">
        {!active ? <EmptyDetail title="WebSocket Detail" body="Select a captured WebSocket connection." /> : <div className="detail-shell">
          <div className="detail-topbar"><div className="detail-title"><h2>{active.host}</h2><div className="url-line">{active.url}</div></div><div className="detail-actions"><a className="secondary" href={`/api/websockets/connections/${encodeURIComponent(active.id)}/export?token=${encodeURIComponent(getToken())}`}><Download />Export</a></div></div>
          <div className="grid metrics-grid compact"><Metric label="Protocol" value={active.protocol} /><Metric label="Frames" value={active.frame_count || 0} /><Metric label="Opened" value={active.created_at} /><Metric label="Closed" value={active.closed_at || "active"} /></div>
          <div className="section-card"><div className="detail-topbar"><h3>Frames</h3><div className="frame-actions"><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search payload, opcode, direction..." /><button className={framesLive ? "primary" : "secondary"} title={framesLive ? "Pause real-time frame updates" : "Enable real-time frame updates"} onClick={() => setFramesLive((value) => !value)}>{framesLive ? <Pause /> : <Play />}{framesLive ? "Pause" : "Live"}</button></div></div><table><thead><tr><th>Time</th><th>Direction</th><th>Opcode</th><th>Bytes</th><th>Payload</th></tr></thead><tbody>{frames.length ? frames.map((frame) => <tr key={frame.id}><td>{timeOnly(frame.created_at)}</td><td>{frame.direction}</td><td>{frame.opcode_name}</td><td>{frame.payload_bytes}</td><td><code>{frame.payload}</code>{frame.truncated && <span className="badge warn">truncated</span>}{frame.injected && <span className="badge allow">injected</span>}</td></tr>) : <tr><td colSpan="5">{framesState.loading ? "Loading frames..." : "No frames."}</td></tr>}</tbody></table><div className="table-footer"><span>{frames.length ? `Showing ${frames.length}${framesHasMore ? "+" : ""} newest frames` : ""}</span>{framesHasMore && <button className="secondary" onClick={() => setFrameLimit((value) => value + framePageSize)}>Load 20 More</button>}</div></div>
          <div className="section-card"><h3>Send Frame</h3><div className="settings-grid"><label>Direction<select value={sendForm.direction} onChange={(e) => setSendForm({ ...sendForm, direction: e.target.value })}><option value="client_to_server">client to server</option><option value="server_to_client">server to client</option></select></label><label>Opcode<select value={sendForm.opcode} onChange={(e) => setSendForm({ ...sendForm, opcode: Number(e.target.value) })}><option value={1}>text</option><option value={2}>binary</option><option value={9}>ping</option><option value={10}>pong</option></select></label></div><textarea value={sendForm.payload} onChange={(e) => setSendForm({ ...sendForm, payload: e.target.value })} /><button className="primary" disabled={!selected} onClick={sendFrame}><Send />Send</button></div>
        </div>}
      </section>
    </div>
  );
}

function TrafficView({ refreshKey, refresh, setCurrent, selectedScope, scopes }) {
  const pageSize = 10;
  const [selected, setSelected] = useState("");
  const [detail, setDetail] = useState(null);
  const [detailError, setDetailError] = useState("");
  const [search, setSearch] = useState("");
  const [live, setLive] = useState(false);
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [listError, setListError] = useState(null);
  const loadingRef = useRef(false);
  const requestRef = useRef(0);
  const searchRef = useRef(search);
  const scopeRef = useRef(selectedScope);
  const selectedRef = useRef(selected);

  useEffect(() => { searchRef.current = search; }, [search]);
  useEffect(() => { scopeRef.current = selectedScope; }, [selectedScope]);
  useEffect(() => { selectedRef.current = selected; }, [selected]);

  const trafficPagePath = (offset) => {
    const params = new URLSearchParams({ limit: String(pageSize), offset: String(offset) });
    if (selectedScope && selectedScope !== "all") params.set("scope_id", selectedScope);
    if (search.trim()) params.set("q", search.trim());
    return `/api/traffic?${params.toString()}`;
  };

  const loadPage = async (offset, replace = false) => {
    if (loadingRef.current) return;
    loadingRef.current = true;
    const requestID = ++requestRef.current;
    if (replace) setLoading(true);
    else setLoadingMore(true);
    setListError(null);
    try {
      const next = await api(trafficPagePath(offset));
      if (requestID !== requestRef.current) return;
      setFlows((current) => replace ? next : [...current, ...next]);
      setHasMore(next.length === pageSize);
    } catch (error) {
      if (requestID === requestRef.current) setListError(error);
    } finally {
      if (requestID === requestRef.current) {
        setLoading(false);
        setLoaded(true);
        setLoadingMore(false);
        loadingRef.current = false;
      }
    }
  };

  useEffect(() => {
    requestRef.current += 1;
    loadingRef.current = false;
    setSelected("");
    setDetail(null);
    setHasMore(true);
    loadPage(0, true);
  }, [refreshKey, selectedScope, search]);

  useEffect(() => {
    if (!live) return undefined;
    const source = new EventSource(`/api/traffic/stream?token=${encodeURIComponent(getToken())}`);
    const trafficTopics = [
      "traffic.request.started",
      "traffic.response.completed",
      "traffic.tunnel.opened",
      "traffic.blocked",
      "traffic.body.captured",
    ];
    let cancelled = false;
    const handleLiveEvent = async (event) => {
      try {
        const payload = JSON.parse(event.data || "{}");
        const id = payload.request_id || payload.id;
        if (!id) return;
        const flow = await api(`/api/traffic/${encodeURIComponent(id)}`);
        if (cancelled || !flowMatchesScope(flow, scopeRef.current) || !flowMatchesSearch(flow, searchRef.current)) return;
        setFlows((current) => {
          const without = current.filter((item) => item.id !== flow.id);
          return [flow, ...without].slice(0, Math.max(pageSize, without.length + 1));
        });
        if (selectedRef.current === id) {
          setDetail(flow);
        }
        setHasMore(true);
      } catch {
        // Live updates are opportunistic; the paged list remains the source of truth.
      }
    };
    trafficTopics.forEach((topic) => source.addEventListener(topic, handleLiveEvent));
    source.onerror = () => {
      source.close();
      if (!cancelled) setLive(false);
    };
    return () => {
      cancelled = true;
      source.close();
    };
  }, [live]);

  useEffect(() => {
    if (!selected && flows.length) setSelected(flows[0].id);
  }, [flows, selected]);

  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setDetailError("");
    const loadDetail = () => api(`/api/traffic/${encodeURIComponent(selected)}`)
      .then((flow) => {
        if (!cancelled) setDetail(flow);
        return flow;
      })
      .catch((err) => {
        if (!cancelled) setDetailError(err.message);
        return null;
      });
    loadDetail().then((flow) => {
      if (cancelled || flow?.request_body || flow?.response_body) return;
      const delays = [500, 1500, 3000];
      delays.forEach((delay) => {
        setTimeout(() => {
          if (!cancelled) loadDetail();
        }, delay);
      });
    });
    return () => { cancelled = true; };
  }, [selected, refreshKey]);

  const handleScroll = (event) => {
    const el = event.currentTarget;
    if (!hasMore || loading || loadingMore || listError) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 64) {
      loadPage(flows.length, false);
    }
  };

  if (!loaded && loading && !flows.length) return <PageState state={{ loading: true }} />;
  if (!loaded && listError && !flows.length) return <PageState state={{ error: listError }} />;
  return (
    <div className="workbench">
      <aside className="workbench-sidebar">
        <div className="workbench-head">
          <div>
            <h2>Traffic</h2>
            <p>Captured requests, responses, and replay sources.</p>
          </div>
          <div className="actions">
            <button className={live ? "primary" : "secondary"} title={live ? "Pause real-time updates" : "Enable real-time updates"} onClick={() => setLive((value) => !value)}>
              {live ? <Pause /> : <Play />}{live ? "Pause" : "Live"}
            </button>
            <button className="secondary" onClick={async () => { await del("/api/traffic"); setSelected(""); refresh(); }}><Trash2 />Clear</button>
            <a className="secondary" download="traffic.json" href={`/api/traffic/export?token=${encodeURIComponent(getToken())}`}><FileJson />JSON</a>
            <a className="secondary" download="traffic.har" href={`/api/traffic/export?format=har&token=${encodeURIComponent(getToken())}`}><Download />HAR</a>
          </div>
          <div className="list-filter">
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder='Search: host:example.com method:POST status:>=400 header:auth body:"token"' />
          </div>
        </div>
        <div className="workbench-list" onScroll={handleScroll}>
          {flows.length ? flows.map((flow) => (
            <FlowRow key={flow.id} flow={flow} scopes={scopes} active={flow.id === selected} onSelect={() => setSelected(flow.id)} />
          )) : <EmptyList>No traffic captured yet.</EmptyList>}
          {loading && flows.length > 0 && <div className="list-status">Filtering...</div>}
          {loadingMore && <div className="list-status">Loading more...</div>}
          {!hasMore && flows.length > 0 && <div className="list-status">End of traffic</div>}
          {listError && flows.length > 0 && <div className="list-status error">Unable to load more.</div>}
        </div>
      </aside>
      <section className="workbench-main">
        {detailError && <div className="detail-shell error">{detailError}</div>}
        {!detail && !detailError && <EmptyDetail title="Request Detail" body="Select a captured flow to inspect headers, parameters, and body samples." />}
        {detail && <TrafficDetail flow={detail} scopes={scopes} setCurrent={setCurrent} refresh={refresh} />}
      </section>
    </div>
  );
}

function FlowRow({ flow, scopes, active, onSelect }) {
  const method = flow.method || "REQ";
  return (
    <button className={`list-row ${active ? "active" : ""}`} onClick={onSelect}>
      <div className="list-row-title">
        <MethodPill method={method} />
        <span>{flow.host || "(unknown host)"}</span>
        <ScopeBadge scopeID={flow.scope_id} scopes={scopes} />
        <ProxyUserBadge username={flow.proxy_user} />
      </div>
      <div className="list-row-meta">{flow.status ? `status ${flow.status}` : "pending"} · {flow.duration_ms !== undefined ? `${flow.duration_ms} ms` : "duration unknown"} · {flow.created_at || ""}</div>
      <div className="list-row-meta">{flow.url || flow.id}</div>
    </button>
  );
}

function TrafficDetail({ flow, scopes, setCurrent, refresh }) {
  const reqHeaders = (flow.headers || []).filter((h) => h.direction === "request");
  const respHeaders = (flow.headers || []).filter((h) => h.direction === "response");
  const [aiState, setAIState] = useState({ loading: false, error: "", note: null });
  const addInterceptRule = async () => {
    const host = flow.host || hostFromURL(flow.url);
    const method = String(flow.method || "GET").toUpperCase();
    const contentType = headerRecordValue(reqHeaders, "Content-Type");
    const rule = {
      name: `Intercept ${method} ${host || "request"}`,
      enabled: true,
      priority: 100,
      direction: "request",
      host_patterns: host ? [host] : [],
      method_patterns: method ? [method] : [],
      status_patterns: [],
      scope_ids: flow.scope_id ? [flow.scope_id] : [],
      content_type_patterns: contentType ? [contentType.split(";")[0].trim()] : [],
    };
    const created = await postJSON("/api/intercept/rules", rule);
    sessionStorage.setItem("selectedInterceptRule", created.id);
    setCurrent("Intercept");
    refresh();
  };
  const runAI = async (action) => {
    setAIState({ loading: true, error: "", note: null });
    try {
      const note = await post(`/api/ai/traffic/${encodeURIComponent(flow.id)}/${action}`);
      setAIState({ loading: false, error: "", note });
    } catch (error) {
      setAIState({ loading: false, error: error.message, note: null });
    }
  };
  return (
    <div className="detail-shell">
      <div className="detail-topbar traffic-detail-head">
        <div className="detail-title">
          <div className="detail-heading-line">
            <h2>{flow.method || "Request"} {flow.host || hostFromURL(flow.url) || "Detail"}</h2>
            <ScopeBadge scopeID={flow.scope_id} scopes={scopes} />
            <ProxyUserBadge username={flow.proxy_user} />
          </div>
          <div className="url-line" title={flow.url || ""}>{flow.url || ""}</div>
        </div>
        <div className="detail-actions">
          <a className="secondary" download={`traffic-${flow.id}.json`} href={`/api/traffic/${encodeURIComponent(flow.id)}/export?token=${encodeURIComponent(getToken())}`}><FileJson />JSON</a>
          <a className="secondary" download={`traffic-${flow.id}.har`} href={`/api/traffic/${encodeURIComponent(flow.id)}/export?format=har&token=${encodeURIComponent(getToken())}`}><Download />HAR</a>
          <button className="secondary" onClick={async () => {
            const created = await postJSON("/api/repeater/cases", { source_flow_id: flow.id });
            sessionStorage.setItem("selectedRepeaterCase", created.id);
            setCurrent("Repeater");
          }}><Repeat />Clone</button>
          <button className="secondary" onClick={addInterceptRule}><Pause />Intercept</button>
          <button className="secondary" onClick={async () => { await post(`/api/traffic/${encodeURIComponent(flow.id)}/replay`); refresh(); }}><Play />Replay</button>
          <button className="secondary" onClick={() => runAI("explain")}><Sparkles />Explain</button>
          <button className="secondary" onClick={() => runAI("suggest-tests")}><Bot />Suggest Tests</button>
        </div>
      </div>
      <AIResultPanel state={aiState} />
      <div className="grid metrics-grid compact">
        <Metric label="Method" value={flow.method || ""} />
        <Metric label="Status" value={flow.status || ""} />
        <Metric label="Duration" value={`${flow.duration_ms || 0} ms`} />
        <Metric label="Cache" value={flow.cache_hit ? "hit" : "miss"} />
        <Metric label="Protocol" value={flow.protocol || ""} />
        <Metric label="Bytes" value={flow.bytes || 0} />
      </div>
      <div className="split-grid">
        <CodeCard title="Query Params" value={flow.query_params || {}} />
        <CodeCard title="Cookies" value={flow.cookies || {}} />
      </div>
      <HeaderTable title="Request Headers" rows={reqHeaders} />
      <HeaderTable title="Response Headers" rows={respHeaders} />
      <div className="split-grid">
        <TextCard title="Request Body Sample" value={flow.request_body || ""} />
        <TextCard title="Response Body Sample" value={flow.response_body || ""} />
      </div>
    </div>
  );
}

function headerRecordValue(headers, name) {
  const target = String(name || "").toLowerCase();
  const found = (headers || []).find((header) => String(header.name || "").toLowerCase() === target);
  return found?.value || "";
}

function hostFromURL(rawURL) {
  try {
    return new URL(rawURL).host;
  } catch {
    return "";
  }
}

function RepeaterView({ refreshKey, refresh, selectedScope, scopes }) {
  const [selected, setSelected] = useState(sessionStorage.getItem("selectedRepeaterCase") || "");
  const state = useAsync(() => api(`/api/repeater/cases${scopeQuery(selectedScope)}`), [refreshKey, selectedScope]);
  const cases = state.data || [];
  const detailState = useAsync(async () => {
    if (!selected) return null;
    return api(`/api/repeater/cases/${encodeURIComponent(selected)}`);
  }, [selected, refreshKey]);

  useEffect(() => {
    if (state.loading) return;
    if (selected && !cases.some((item) => item.id === selected)) {
      sessionStorage.removeItem("selectedRepeaterCase");
      setSelected(cases[0]?.id || "");
      return;
    }
    if (!selected && cases.length) setSelected(cases[0].id);
  }, [cases, selected, state.loading]);

  useEffect(() => {
    if (isNotFound(detailState.error)) {
      sessionStorage.removeItem("selectedRepeaterCase");
      setSelected("");
    }
  }, [detailState.error]);

  useEffect(() => {
    if (selected) {
      sessionStorage.setItem("selectedRepeaterCase", selected);
    } else {
      sessionStorage.removeItem("selectedRepeaterCase");
    }
  }, [cases, selected]);

  if (state.loading || state.error) return <PageState state={state} />;
  const detail = detailState.data;
  const detailError = isNotFound(detailState.error) ? null : detailState.error;
  return (
    <div className="workbench">
      <aside className="workbench-sidebar">
        <div className="workbench-head">
          <div>
            <h2>Repeater</h2>
            <p>Saved research requests and response history.</p>
          </div>
          <div className="actions">
            <button className="secondary" onClick={async () => {
              const created = await postJSON("/api/repeater/cases", {
                name: "New repeater case",
                method: "GET",
                url: "http://example.com/",
                headers: {},
                body: "",
                timeout_ms: 30000,
                scope_id: isConcreteScope(selectedScope) ? selectedScope : "",
              });
              setSelected(created.id);
              refresh();
            }}><Plus />New</button>
          </div>
        </div>
        <div className="workbench-list">
          {cases.length ? cases.map((c) => <RepeaterRow key={c.id} item={c} scopes={scopes} active={c.id === selected} onSelect={() => setSelected(c.id)} />) : <EmptyList>No saved cases yet.</EmptyList>}
        </div>
      </aside>
      <section className="workbench-main">
        {detailError && <div className="detail-shell error">{detailError.message}</div>}
        {!detail && !detailError && <EmptyDetail title="Request Builder" body="Create a case or clone a captured request from Traffic." />}
        {detail && <RepeaterEditor detail={detail} scopes={scopes} refresh={refresh} clearSelected={() => setSelected("")} />}
      </section>
    </div>
  );
}

function isNotFound(error) {
  return Boolean(error && /^404\b/.test(error.message || ""));
}

function RepeaterRow({ item, scopes, active, onSelect }) {
  return (
    <button className={`list-row ${active ? "active" : ""}`} onClick={onSelect}>
      <div className="list-row-title">
        <MethodPill method={item.method || "REQ"} />
        <span>{item.name || item.id}</span>
        <ScopeBadge scopeID={item.scope_id} scopes={scopes} />
      </div>
      <div className="list-row-meta">{item.url || ""}</div>
      <div className="list-row-meta">{item.source_flow_id ? `source ${item.source_flow_id}` : "manual case"} - {item.updated_at || ""}</div>
    </button>
  );
}

function RepeaterEditor({ detail, scopes, refresh, clearSelected }) {
  const c = detail.case;
  const runs = detail.runs || [];
  const [form, setForm] = useState(() => ({
    name: c.name || "",
    method: c.method || "GET",
    url: c.url || "",
    timeout_ms: c.timeout_ms || 30000,
    headersText: JSON.stringify(c.headers || {}, null, 2),
    body: c.body || "",
  }));
  const [selectedRun, setSelectedRun] = useState(runs[0]?.id || "");
  const currentRun = runs.find((run) => run.id === selectedRun) || runs[0];
  const previousRun = runs[runs.findIndex((run) => run.id === currentRun?.id) + 1];
  const [aiState, setAIState] = useState({ loading: false, error: "", note: null });
  const update = (key, value) => setForm((prev) => ({ ...prev, [key]: value }));
  const payload = () => ({
    name: form.name,
    method: form.method,
    url: form.url,
    timeout_ms: Number(form.timeout_ms),
    headers: parseJSONEditorValue(form.headersText, {}),
    body: form.body,
  });
  const save = async () => {
    await putJSON(`/api/repeater/cases/${encodeURIComponent(c.id)}`, payload());
    refresh();
  };
  const runAI = async (action) => {
    setAIState({ loading: true, error: "", note: null });
    try {
      const note = await post(`/api/ai/repeater/cases/${encodeURIComponent(c.id)}/${action}`);
      setAIState({ loading: false, error: "", note });
    } catch (error) {
      setAIState({ loading: false, error: error.message, note: null });
    }
  };

  return (
    <div className="detail-shell">
      <div className="detail-topbar">
          <div className="detail-title">
            <h2>Request Builder</h2>
            <ScopeBadge scopeID={c.scope_id} scopes={scopes} />
            <div className="url-line">{c.name || c.id}</div>
        </div>
        <div className="detail-actions">
          <button className="secondary" onClick={save}><Save />Save</button>
          <button className="primary" onClick={async () => { await save(); await post(`/api/repeater/cases/${encodeURIComponent(c.id)}/send`); refresh(); }}><Send />Send</button>
          <button className="secondary" onClick={() => runAI("suggest-tests")}><Bot />Suggest Tests</button>
          <button className="secondary" disabled={runs.length < 2} onClick={() => runAI("compare-runs")}><Sparkles />Compare Runs</button>
          <button className="secondary danger-button" onClick={async () => { await del(`/api/repeater/cases/${encodeURIComponent(c.id)}`); clearSelected(); refresh(); }}><Trash2 />Delete</button>
        </div>
      </div>
      <AIResultPanel state={aiState} />
      <div className="editor-stack">
        <label>Name<input value={form.name} onChange={(e) => update("name", e.target.value)} /></label>
        <div className="request-line">
          <label>Method<input value={form.method} onChange={(e) => update("method", e.target.value)} /></label>
          <label>URL<input value={form.url} onChange={(e) => update("url", e.target.value)} /></label>
          <label>Timeout ms<input type="number" value={form.timeout_ms} onChange={(e) => update("timeout_ms", e.target.value)} /></label>
        </div>
        <div className="split-grid">
          <JsonEditor title="Headers JSON" value={form.headersText} onChange={(value) => update("headersText", value)} />
          <div className="section-card"><h3>Request Body</h3><textarea value={form.body} onChange={(e) => update("body", e.target.value)} /></div>
        </div>
        <div className="section-card">
          <h3>Run History</h3>
          <table className="kv-table"><thead><tr><th>Time</th><th>Status</th><th>Duration</th><th>Bytes</th><th>Error</th></tr></thead><tbody>
            {runs.length ? runs.map((run) => (
              <tr key={run.id}>
                <td><button className="rowbutton" onClick={() => setSelectedRun(run.id)}>{run.created_at}</button></td>
                <td>{run.status || ""}</td>
                <td>{run.duration_ms || 0} ms</td>
                <td>{run.bytes || 0}</td>
                <td>{run.error || ""}</td>
              </tr>
            )) : <tr><td colSpan="5">No runs yet.</td></tr>}
          </tbody></table>
        </div>
        {currentRun && <RunDetail run={currentRun} previous={previousRun} />}
      </div>
    </div>
  );
}

function RunDetail({ run, previous }) {
  return (
    <>
      <CodeCard title="Run Detail" value={run} />
      <ResponsePreview run={run} />
      <CodeCard title="Comparison" value={compareRuns(run, previous)} />
    </>
  );
}

function ResponsePreview({ run }) {
  const body = run.response_body || "";
  if (!body) return null;
  if (isHTMLResponse(run)) {
    return (
      <div className="section-card">
        <h3>Sandboxed Response Preview</h3>
        <iframe className="sandbox-preview" sandbox="" referrerPolicy="no-referrer" srcDoc={body} title="Sandboxed response preview" />
      </div>
    );
  }
  return <TextCard title="Response Body" value={body} />;
}

function isHTMLResponse(run) {
  const contentType = headerValue(run.response_headers || {}, "content-type").toLowerCase();
  return contentType.includes("text/html") || /^\s*<!doctype html/i.test(run.response_body || "") || /^\s*<html[\s>]/i.test(run.response_body || "");
}

function headerValue(headers, name) {
  const target = name.toLowerCase();
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() === target) {
      const value = headers[key];
      return Array.isArray(value) ? value.join(", ") : String(value || "");
    }
  }
  return "";
}

function compareRuns(run, previous) {
  if (!previous) return { baseline: "no previous run" };
  const currentHeaders = Object.keys(run.response_headers || {}).sort();
  const previousHeaders = Object.keys(previous.response_headers || {}).sort();
  return {
    status_changed: run.status !== previous.status,
    previous_status: previous.status || 0,
    current_status: run.status || 0,
    body_length_delta: (run.response_body || "").length - (previous.response_body || "").length,
    headers_added: currentHeaders.filter((h) => !previousHeaders.includes(h)),
    headers_removed: previousHeaders.filter((h) => !currentHeaders.includes(h)),
  };
}

function AIResultPanel({ state }) {
  if (!state.loading && !state.error && !state.note) return null;
  return (
    <div className="section-card ai-result">
      <h3>AI Copilot</h3>
      {state.loading && <p className="muted">Asking the research copilot...</p>}
      {state.error && <p className="error-text">Unable to run AI action: {state.error}</p>}
      {state.note && (
        <>
          <div className="note-head">
            <strong>{state.note.title}</strong>
            <span className="muted">{state.note.model || "local guardrail"}</span>
          </div>
          {state.note.summary && <p>{state.note.summary}</p>}
          <AIContent content={state.note.content_json || {}} />
          <p className="muted">Saved as research note {state.note.id}</p>
        </>
      )}
    </div>
  );
}

function AIContent({ content }) {
  const payload = typeof content === "string" ? safeParseJSON(content) : content;
  if (!payload || typeof payload !== "object") return <pre>{String(content || "")}</pre>;
  return (
    <div className="ai-content">
      {Object.entries(payload).map(([key, value]) => (
        <div key={key} className="ai-content-row">
          <strong>{humanLabel(key)}</strong>
          {Array.isArray(value) ? (
            value.length ? <ul>{value.map((item, idx) => <li key={`${key}-${idx}`}>{String(item)}</li>)}</ul> : <p className="muted">None.</p>
          ) : <p>{String(value || "")}</p>}
        </div>
      ))}
    </div>
  );
}

function safeParseJSON(value) {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function humanLabel(value) {
  return String(value || "").replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function PentestToolkitView({ refreshKey, refresh, selectedScope, scopes, setCurrent }) {
  const [selectedMap, setSelectedMap] = useState("");
  const [tab, setTab] = useState("endpoints");
  const [selectedItem, setSelectedItem] = useState(null);
  const [severity, setSeverity] = useState("all");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const mapsState = useAsync(() => api(`/api/pentest/maps${scopeQuery(selectedScope)}`), [refreshKey, selectedScope]);
  const maps = mapsState.data || [];
  const detailState = useAsync(async () => selectedMap ? api(`/api/pentest/maps/${encodeURIComponent(selectedMap)}`) : null, [selectedMap, refreshKey]);
  const detail = detailState.data;
  const endpoints = detail?.endpoints || [];
  const parameters = detail?.parameters || [];
  const observations = (detail?.observations || []).filter((item) => severity === "all" || item.severity === severity);

  useEffect(() => {
    if (!selectedMap && maps.length) setSelectedMap(maps[0].id);
    if (selectedMap && maps.length && !maps.some((m) => m.id === selectedMap)) setSelectedMap(maps[0].id);
  }, [maps, selectedMap]);

  const rebuild = async () => {
    setBusy(true);
    setError("");
    try {
      const created = await postJSON("/api/pentest/maps/rebuild", {
        scope_id: selectedScope && selectedScope !== "all" ? selectedScope : "",
        include_out_of_scope: selectedScope === "all",
        name: pentestMapName(selectedScope, scopes),
      });
      setSelectedMap(created.map.id);
      setSelectedItem(null);
      refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const cloneEndpoint = async (endpoint) => {
    if (!detail?.map?.id || !endpoint?.id) return;
    const created = await postJSON(`/api/pentest/maps/${encodeURIComponent(detail.map.id)}/endpoints/${encodeURIComponent(endpoint.id)}/clone`, {});
    sessionStorage.setItem("selectedRepeaterCase", created.id);
    setCurrent("Repeater");
  };

  if (mapsState.loading) return <PageState state={mapsState} />;
  return (
    <div className="workbench">
      <aside className="workbench-sidebar">
        <div className="workbench-head">
          <div className="workbench-head-row">
            <div><h2>Pentest Toolkit</h2><p>Passive target maps from captured traffic.</p></div>
            <div className="actions"><button className="secondary" disabled={busy} onClick={rebuild}><RefreshCw />{busy ? "Rebuilding..." : "Rebuild Map"}</button></div>
          </div>
          {error && <p className="error-text">{error}</p>}
        </div>
        <div className="workbench-list">
          {maps.length ? maps.map((m) => (
            <button key={m.id} className={`list-row ${m.id === selectedMap ? "active" : ""}`} onClick={() => { setSelectedMap(m.id); setSelectedItem(null); }}>
              <div className="list-row-title"><Crosshair /><span>{m.name}</span><ScopeBadge scopeID={m.scope_id} scopes={scopes} /></div>
              <div className="list-row-meta">{m.endpoint_count} endpoints · {m.parameter_count} params · {m.source_flow_count} flows</div>
              <div className="list-row-meta">{m.updated_at}</div>
            </button>
          )) : <EmptyList>No target maps yet. Capture traffic, then rebuild a map.</EmptyList>}
        </div>
      </aside>
      <section className="workbench-main">
        {!selectedMap && <EmptyDetail title="Target Mapper" body="Rebuild a map to inventory endpoints, parameters, cookies, and passive hints from captured traffic." />}
        {selectedMap && detailState.loading && <PageState state={detailState} />}
        {selectedMap && detailState.error && <PageState state={detailState} />}
        {detail && (
          <div className="detail-shell">
            <div className="detail-topbar">
              <div className="detail-title"><h2>{detail.map.name}</h2><ScopeBadge scopeID={detail.map.scope_id} scopes={scopes} /><div className="url-line">Updated {detail.map.updated_at}</div></div>
              <div className="detail-actions"><button className="secondary danger-button" onClick={async () => { await del(`/api/pentest/maps/${detail.map.id}`); setSelectedMap(""); setSelectedItem(null); refresh(); }}><Trash2 />Delete</button></div>
            </div>
            <div className="grid metrics-grid compact">
              <Metric label="Flows" value={detail.map.source_flow_count} />
              <Metric label="Endpoints" value={detail.map.endpoint_count} />
              <Metric label="Parameters" value={detail.map.parameter_count} />
              <Metric label="Hints" value={detail.observations.length} />
            </div>
            <div className="tabs">
              {["endpoints", "parameters", "cookies", "hints"].map((name) => <button key={name} className={tab === name ? "active" : ""} onClick={() => { setTab(name); setSelectedItem(null); }}>{name}</button>)}
            </div>
            {tab === "endpoints" && <PentestEndpointTable endpoints={endpoints} parameters={parameters} selected={selectedItem} onSelect={setSelectedItem} />}
            {tab === "parameters" && <PentestParameterTable title="Parameters" parameters={parameters} selected={selectedItem} onSelect={setSelectedItem} />}
            {tab === "cookies" && <PentestParameterTable title="Cookies" parameters={parameters.filter((p) => p.location === "cookie")} selected={selectedItem} onSelect={setSelectedItem} />}
            {tab === "hints" && <PentestObservationTable observations={observations} severity={severity} setSeverity={setSeverity} selected={selectedItem} onSelect={setSelectedItem} />}
            <PentestDetail item={selectedItem} endpoints={endpoints} onClone={cloneEndpoint} />
          </div>
        )}
      </section>
    </div>
  );
}

function PentestEndpointTable({ endpoints, parameters, selected, onSelect }) {
  const { visibleItems, hasMore, loadMore } = usePagedRows(endpoints);
  return (
    <div className="section-card">
      <h3>Endpoints</h3>
      <table>
        <thead><tr><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Types</th><th>Params</th></tr></thead>
        <tbody>{endpoints.length ? visibleItems.map((e) => <tr key={e.id} className={selected?.id === e.id ? "selected-row" : ""} onClick={() => onSelect({ type: "endpoint", ...e })}><td><MethodPill method={e.method} /></td><td>{e.host}</td><td><code>{e.normalized_path}</code></td><td>{Object.keys(e.status_summary || {}).join(", ")}</td><td>{(e.content_types || []).join(", ")}</td><td>{parameters.filter((p) => p.endpoint_id === e.id).length}</td></tr>) : <tr><td colSpan="6">No endpoints mapped.</td></tr>}</tbody>
      </table>
      <LoadMoreRows visible={visibleItems.length} total={endpoints.length} hasMore={hasMore} onLoadMore={loadMore} />
    </div>
  );
}

function PentestParameterTable({ title, parameters, selected, onSelect }) {
  const { visibleItems, hasMore, loadMore } = usePagedRows(parameters);
  return (
    <div className="section-card">
      <h3>{title}</h3>
      <table>
        <thead><tr><th>Name</th><th>Location</th><th>Types</th><th>Endpoints</th><th>Flags</th></tr></thead>
        <tbody>{parameters.length ? visibleItems.map((p) => <tr key={p.id} className={selected?.id === p.id ? "selected-row" : ""} onClick={() => onSelect({ type: "parameter", ...p })}><td><code>{p.name}</code></td><td>{p.location}</td><td>{(p.observed_types || []).join(", ")}</td><td>{p.endpoint_count}</td><td>{p.interesting && <span className="badge warn">interesting</span>} {p.reflected && <span className="badge allow">reflected</span>}</td></tr>) : <tr><td colSpan="5">No {String(title || "parameters").toLowerCase()} mapped.</td></tr>}</tbody>
      </table>
      <LoadMoreRows visible={visibleItems.length} total={parameters.length} hasMore={hasMore} onLoadMore={loadMore} />
    </div>
  );
}

function PentestObservationTable({ observations, severity, setSeverity, selected, onSelect }) {
  const { visibleItems, hasMore, loadMore } = usePagedRows(observations);
  return (
    <div className="section-card">
      <div className="detail-topbar"><h3>Passive Hints</h3><select value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="all">all severities</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option><option value="info">info</option></select></div>
      <table>
        <thead><tr><th>Severity</th><th>Kind</th><th>Title</th><th>Flow</th></tr></thead>
        <tbody>{observations.length ? visibleItems.map((o) => <tr key={o.id} className={selected?.id === o.id ? "selected-row" : ""} onClick={() => onSelect({ type: "observation", ...o })}><td><span className={`badge ${o.severity === "medium" || o.severity === "high" ? "warn" : "allow"}`}>{o.severity}</span></td><td>{o.kind}</td><td>{o.title}</td><td><code>{o.representative_flow_id}</code></td></tr>) : <tr><td colSpan="4">No passive hints for this filter.</td></tr>}</tbody>
      </table>
      <LoadMoreRows visible={visibleItems.length} total={observations.length} hasMore={hasMore} onLoadMore={loadMore} />
    </div>
  );
}

function usePagedRows(items, pageSize = 10) {
  const [visibleCount, setVisibleCount] = useState(pageSize);
  const rows = items || [];
  const rowSignature = rows.map((row) => row.id || row.name || row.title || JSON.stringify(row)).join("\x1f");
  useEffect(() => {
    setVisibleCount(pageSize);
  }, [rowSignature, pageSize]);
  return {
    visibleItems: rows.slice(0, visibleCount),
    hasMore: visibleCount < rows.length,
    loadMore: () => setVisibleCount((count) => count + pageSize),
  };
}

function LoadMoreRows({ visible, total, hasMore, onLoadMore }) {
  if (!total || total <= 10) return null;
  return (
    <div className="table-footer">
      <span>Showing {visible} of {total}</span>
      {hasMore && <button className="secondary" onClick={onLoadMore}>Load 10 More</button>}
    </div>
  );
}

function PentestDetail({ item, endpoints, onClone }) {
  if (!item) return <EmptyDetail title="Pentest Detail" body="Select an endpoint, parameter, cookie, or passive hint to inspect evidence." />;
  const endpoint = item.type === "endpoint" ? item : endpoints.find((e) => e.id === item.endpoint_id);
  return <div className="section-card"><div className="detail-topbar"><h3>{item.type === "endpoint" ? item.normalized_path : item.title || item.name}</h3>{endpoint && <button className="secondary" onClick={() => onClone(endpoint)}><Repeat />Clone to Repeater</button>}</div><CodeCard title="Evidence" value={item} /></div>;
}

function pentestMapName(selectedScope, scopes) {
  if (!selectedScope || selectedScope === "all") return "All traffic map";
  if (selectedScope === "__out_of_scope__") return "Out of scope map";
  const scope = (scopes || []).find((s) => s.id === selectedScope);
  return `${scope?.name || "Scope"} map`;
}

function AICopilotView({ refreshKey, refresh, selectedScope, scopes, setCurrent }) {
  const [targetType, setTargetType] = useState("");
  const query = new URLSearchParams({ limit: "100" });
  if (targetType) query.set("target_type", targetType);
  if (selectedScope && selectedScope !== "all") query.set("scope_id", selectedScope);
  const state = useAsync(() => api(`/api/ai/notes?${query.toString()}`), [refreshKey, selectedScope, targetType]);
  const [selected, setSelected] = useState("");
  const notes = state.data || [];
  const active = notes.find((note) => note.id === selected) || notes[0];

  useEffect(() => {
    if (notes.length && !notes.some((note) => note.id === selected)) setSelected(notes[0].id);
    if (!notes.length) setSelected("");
  }, [notes, selected]);

  if (state.loading || state.error) return <PageState state={state} />;
  return (
    <div className="workbench">
      <aside className="workbench-sidebar">
        <div className="workbench-head">
          <div>
            <h2>AI Copilot</h2>
            <p>Saved AI research notes and analysis.</p>
          </div>
          <div className="list-filter">
            <select value={targetType} onChange={(e) => setTargetType(e.target.value)}>
              <option value="">All targets</option>
              <option value="traffic">Traffic</option>
              <option value="repeater_case">Repeater cases</option>
              <option value="repeater_run">Repeater runs</option>
              <option value="threat_event">Threat events</option>
              <option value="scope">Scopes</option>
            </select>
          </div>
        </div>
        <div className="workbench-list">
          {notes.length ? notes.map((note) => (
            <button key={note.id} className={`list-row ${active?.id === note.id ? "active" : ""}`} onClick={() => setSelected(note.id)}>
              <div className="list-row-title">
                <Bot />
                <span>{note.title}</span>
                <ScopeBadge scopeID={note.scope_id} scopes={scopes} />
              </div>
              <div className="list-row-meta">{note.kind} - {note.target_type}:{note.target_id}</div>
              <div className="list-row-meta">{note.created_at}</div>
            </button>
          )) : <EmptyList>No AI notes saved yet.</EmptyList>}
        </div>
      </aside>
      <section className="workbench-main">
        {!active ? <EmptyDetail title="AI Note Detail" body="Run an AI action from Traffic or Repeater to save research notes." /> : (
          <div className="detail-shell">
            <div className="detail-topbar">
              <div className="detail-title">
                <h2>{active.title}</h2>
                <ScopeBadge scopeID={active.scope_id} scopes={scopes} />
                <div className="url-line">{active.target_type}:{active.target_id}</div>
              </div>
              <div className="detail-actions">
                {active.target_type === "traffic" && <button className="secondary" onClick={() => setCurrent("Traffic")}>Open Traffic</button>}
                {active.target_type === "repeater_case" && <button className="secondary" onClick={() => { sessionStorage.setItem("selectedRepeaterCase", active.target_id); setCurrent("Repeater"); }}>Open Repeater</button>}
                <button className="secondary danger-button" onClick={async () => { await del(`/api/ai/notes/${encodeURIComponent(active.id)}`); refresh(); }}><Trash2 />Delete</button>
              </div>
            </div>
            <div className="grid metrics-grid compact">
              <Metric label="Kind" value={active.kind} />
              <Metric label="Model" value={active.model || "local"} />
              <Metric label="Created" value={active.created_at} />
              <Metric label="Prompt hash" value={active.prompt_hash || ""} />
            </div>
            {active.summary && <div className="section-card"><h3>Summary</h3><p>{active.summary}</p></div>}
            <div className="section-card"><h3>Content</h3><AIContent content={active.content_json || {}} /></div>
          </div>
        )}
      </section>
    </div>
  );
}

function TimelineView({ refreshKey, selectedScope }) {
  const pageSize = 20;
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState("");
  const [host, setHost] = useState("");
  const [live, setLive] = useState(true);
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState(null);
  const [hasMore, setHasMore] = useState(true);
  const loadingRef = useRef(false);
  const requestRef = useRef(0);
  const entriesRef = useRef([]);
  const filterSignature = `${selectedScope}\n${search}\n${kind}\n${host}`;

  useEffect(() => { entriesRef.current = entries; }, [entries]);

  const timelinePath = (offset) => {
    const params = new URLSearchParams({ limit: String(pageSize), offset: String(offset) });
    if (search.trim()) params.set("q", search.trim());
    if (kind) params.set("kind", kind);
    if (host.trim()) params.set("host", host.trim());
    if (selectedScope && selectedScope !== "all") params.set("scope_id", selectedScope);
    return `/api/timeline?${params.toString()}`;
  };

  const mergeTimelineEntries = (current, next, prepend = false) => {
    const seen = new Set();
    const combined = prepend ? [...next, ...current] : [...current, ...next];
    return combined.filter((entry) => {
      if (!entry?.id || seen.has(entry.id)) return false;
      seen.add(entry.id);
      return true;
    });
  };

  const loadTimelinePage = async (offset, replace = false) => {
    if (loadingRef.current) return;
    loadingRef.current = true;
    const requestID = ++requestRef.current;
    if (replace) setLoading(true);
    else setLoadingMore(true);
    setError(null);
    try {
      const next = await api(timelinePath(offset));
      if (requestID !== requestRef.current) return;
      setEntries((current) => replace ? next : mergeTimelineEntries(current, next));
      setHasMore(next.length === pageSize);
    } catch (err) {
      if (requestID === requestRef.current) setError(err);
    } finally {
      if (requestID === requestRef.current) {
        setLoading(false);
        setLoadingMore(false);
        loadingRef.current = false;
      }
    }
  };

  const refreshNewest = async () => {
    const requestID = ++requestRef.current;
    try {
      const next = await api(timelinePath(0));
      if (requestID !== requestRef.current) return;
      setEntries((current) => mergeTimelineEntries(current, next, true));
      setHasMore(next.length === pageSize || entriesRef.current.length > pageSize);
    } catch {
      // Keep the current timeline stable during transient live-refresh errors.
    }
  };

  useEffect(() => {
    requestRef.current += 1;
    loadingRef.current = false;
    setEntries([]);
    setHasMore(true);
    loadTimelinePage(0, true);
  }, [refreshKey, filterSignature]);

  useEffect(() => {
    const page = document.querySelector(".page");
    if (!page) return undefined;
    const onScroll = () => {
      if (!hasMore || loadingRef.current || loadingMore || loading) return;
      const remaining = page.scrollHeight - page.scrollTop - page.clientHeight;
      if (remaining < 360) loadTimelinePage(entriesRef.current.length, false);
    };
    page.addEventListener("scroll", onScroll, { passive: true });
    return () => page.removeEventListener("scroll", onScroll);
  }, [hasMore, loadingMore, loading, filterSignature]);

  useEffect(() => {
    if (!live) return undefined;
    const source = new EventSource(`/api/traffic/stream?token=${encodeURIComponent(getToken())}`);
    let timer = null;
    const refreshSoon = () => {
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        refreshNewest();
      }, 500);
    };
    [
      "traffic.request.started",
      "traffic.response.completed",
      "traffic.tunnel.opened",
      "traffic.blocked",
      "cache.hit",
      "cache.miss",
      "intercept.pending",
      "intercept.resolved",
      "websocket.connection",
      "websocket.frame",
      "fault.injected",
      "config.updated",
    ].forEach((topic) => source.addEventListener(topic, refreshSoon));
    source.onerror = () => {
      source.close();
      setLive(false);
    };
    return () => {
      source.close();
      if (timer) clearTimeout(timer);
    };
  }, [live, filterSignature]);

  const kinds = ["traffic", "tunnel", "cache", "blocked", "intercept", "websocket", "fault", "config", "profile"];
  return (
    <div className="page-stack">
      <PageTitle title="Timeline" subtitle="Chronological request, cache, intercept, WebSocket, threat, and fault activity." actions={<button className={live ? "primary" : "secondary"} onClick={() => setLive((value) => !value)}>{live ? <Pause /> : <Play />}{live ? "Pause" : "Live"}</button>} />
      <div className="panel">
        <div className="settings-grid">
          <label>Search<input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="host, URL, status, summary..." /></label>
          <label>Kind<select value={kind} onChange={(e) => setKind(e.target.value)}><option value="">All kinds</option>{kinds.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
          <label>Host<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="api.example.test" /></label>
        </div>
      </div>
      <div className="panel">
        {error && <p className="error-text">{error.message || String(error)}</p>}
        <table>
          <thead><tr><th>Time</th><th>Kind</th><th>Host</th><th>Request</th><th>Status</th><th>Duration</th><th>Summary</th></tr></thead>
          <tbody>{entries.length ? entries.map((entry) => <tr key={entry.id}>
            <td>{timeOnly(entry.created_at)}</td>
            <td><span className={`badge ${entry.kind}`}>{entry.kind}</span></td>
            <td>{entry.host}</td>
            <td><span className="method-pill small">{entry.method || "-"}</span> <span title={entry.url}>{entry.url || entry.request_id || entry.connection_id}</span></td>
            <td>{entry.status || ""}</td>
            <td>{entry.duration_ms ? `${entry.duration_ms} ms` : ""}</td>
            <td>{entry.summary}{entry.severity && <span className={`badge ${entry.severity}`}>{entry.severity}</span>}</td>
          </tr>) : <tr><td colSpan="7">{loading ? "Loading timeline..." : "No timeline entries yet."}</td></tr>}</tbody>
        </table>
        <div className="list-status">{loadingMore ? "Loading older entries..." : hasMore && entries.length ? "Scroll for older entries." : entries.length ? "End of timeline." : ""}</div>
      </div>
    </div>
  );
}

function FaultsView({ refreshKey, refresh, selectedScope }) {
  const emptyRule = { name: "", enabled: true, priority: 100, phase: "request", action: "delay", host_patterns: [], url_patterns: [], method_patterns: [], scope_ids: [], delay_ms: 500, throttle_bytes_per_second: 1024, corrupt_probability: 1, corrupt_mode: "flip_byte", synthetic_status: 503, synthetic_headers: { "Content-Type": ["text/plain; charset=utf-8"] }, synthetic_body: "synthetic fault response\n" };
  const [selectedID, setSelectedID] = useState("");
  const [form, setForm] = useState(emptyRule);
  const [testForm, setTestForm] = useState({ phase: "request", method: "GET", url: "https://example.test/", host: "example.test", scope_id: selectedScope === "all" ? "" : selectedScope });
  const [testResult, setTestResult] = useState(null);
  const [headersText, setHeadersText] = useState(JSON.stringify(emptyRule.synthetic_headers, null, 2));
  const [saveError, setSaveError] = useState("");
  const state = useAsync(() => api("/api/faults/rules"), [refreshKey]);

  useEffect(() => {
    const rule = (state.data || []).find((item) => item.id === selectedID);
    if (rule) {
      setForm(rule);
      setHeadersText(JSON.stringify(rule.synthetic_headers || {}, null, 2));
    }
  }, [selectedID, state.data]);

  if (state.loading || state.error) return <PageState state={state} />;
  const rules = Array.isArray(state.data) ? state.data : [];
  const save = async () => {
    setSaveError("");
    try {
      const payload = { ...form, synthetic_headers: parseJSONEditorValue(headersText, {}) };
      if (selectedID) await putJSON(`/api/faults/rules/${encodeURIComponent(selectedID)}`, payload);
      else {
        const created = await postJSON("/api/faults/rules", payload);
        setSelectedID(created.id);
      }
      refresh();
    } catch (err) {
      setSaveError(err.message);
    }
  };
  return (
    <div className="workbench">
      <aside className="workbench-sidebar">
        <div className="workbench-head"><div><h2>Faults</h2><p>HTTP latency and failure injection.</p></div><button className="secondary" onClick={() => { setSelectedID(""); setForm(emptyRule); setHeadersText(JSON.stringify(emptyRule.synthetic_headers, null, 2)); }}><Plus />New</button></div>
        <div className="workbench-list">{rules.length ? rules.map((rule) => <button key={rule.id} className={`list-row ${rule.id === selectedID ? "active" : ""}`} onClick={() => setSelectedID(rule.id)}><div className="list-row-title"><span className={`badge ${rule.action}`}>{rule.action}</span><span>{rule.name}</span></div><div className="list-row-meta">{rule.phase} - priority {rule.priority} - {rule.enabled ? "enabled" : "disabled"}</div></button>) : <EmptyList>No fault rules yet.</EmptyList>}</div>
      </aside>
      <section className="workbench-main">
        <div className="detail-shell">
          <div className="detail-topbar"><div><h2>{selectedID ? "Edit Fault Rule" : "New Fault Rule"}</h2></div><div className="detail-actions"><button className="primary" onClick={save}><Save />Save</button>{selectedID && <button className="secondary danger-button" onClick={async () => { await del(`/api/faults/rules/${encodeURIComponent(selectedID)}`); setSelectedID(""); setForm(emptyRule); refresh(); }}><Trash2 />Delete</button>}</div></div>
          {saveError && <p className="error-text">{saveError}</p>}
          <div className="settings-grid">
            <label>Name<input value={form.name || ""} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
            <label>Priority<input type="number" value={form.priority || 100} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} /></label>
            <label>Phase<select value={form.phase || "request"} onChange={(e) => setForm({ ...form, phase: e.target.value })}><option value="request">request</option><option value="response">response</option></select></label>
            <label>Action<select value={form.action || "delay"} onChange={(e) => setForm({ ...form, action: e.target.value })}><option value="delay">delay</option><option value="drop">drop</option><option value="throttle">throttle</option><option value="corrupt">corrupt</option><option value="synthetic_response">synthetic response</option></select></label>
            <label><input type="checkbox" checked={form.enabled !== false} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} /> Enabled</label>
          </div>
          <div className="split-grid">
            <PatternEditor title="Hosts" placeholder={"example.com\n*.example.com"} values={form.host_patterns || []} onChange={(values) => setForm({ ...form, host_patterns: values })} />
            <PatternEditor title="URLs" placeholder={"*/api/*\n*checkout*"} values={form.url_patterns || []} onChange={(values) => setForm({ ...form, url_patterns: values })} />
            <PatternEditor title="Methods" placeholder={"GET\nPOST"} values={form.method_patterns || []} onChange={(values) => setForm({ ...form, method_patterns: values })} />
            <PatternEditor title="Scope IDs" placeholder={"scope-id"} values={form.scope_ids || []} onChange={(values) => setForm({ ...form, scope_ids: values })} />
          </div>
          <div className="settings-grid">
            <label>Delay ms<input type="number" value={form.delay_ms || 0} onChange={(e) => setForm({ ...form, delay_ms: Number(e.target.value) })} /></label>
            <label>Throttle B/s<input type="number" value={form.throttle_bytes_per_second || 0} onChange={(e) => setForm({ ...form, throttle_bytes_per_second: Number(e.target.value) })} /></label>
            <label>Corrupt probability<input type="number" step="0.01" min="0" max="1" value={form.corrupt_probability ?? 1} onChange={(e) => setForm({ ...form, corrupt_probability: Number(e.target.value) })} /></label>
            <label>Synthetic status<input type="number" value={form.synthetic_status || 503} onChange={(e) => setForm({ ...form, synthetic_status: Number(e.target.value) })} /></label>
          </div>
          <div className="split-grid"><JsonEditor title="Synthetic Headers JSON" value={headersText} onChange={setHeadersText} /><TextCard title="Synthetic Body" value={form.synthetic_body || ""} onChange={(value) => setForm({ ...form, synthetic_body: value })} /></div>
        </div>
        <div className="detail-shell">
          <h2>Matcher Test</h2>
          <div className="settings-grid">
            <label>Phase<select value={testForm.phase} onChange={(e) => setTestForm({ ...testForm, phase: e.target.value })}><option value="request">request</option><option value="response">response</option></select></label>
            <label>Method<input value={testForm.method} onChange={(e) => setTestForm({ ...testForm, method: e.target.value })} /></label>
            <label>URL<input value={testForm.url} onChange={(e) => setTestForm({ ...testForm, url: e.target.value })} /></label>
            <label>Host<input value={testForm.host} onChange={(e) => setTestForm({ ...testForm, host: e.target.value })} /></label>
          </div>
          <button className="secondary" onClick={async () => setTestResult(await postJSON("/api/faults/test", testForm))}>Test Rule</button>
          <pre>{testResult ? JSON.stringify(testResult, null, 2) : ""}</pre>
        </div>
      </section>
    </div>
  );
}

function HostProfilesView({ refreshKey, refresh }) {
  const emptyProfile = { name: "", enabled: true, priority: 100, host_patterns: [], url_patterns: [], method_patterns: [], overrides: {} };
  const [selectedID, setSelectedID] = useState("");
  const [form, setForm] = useState(emptyProfile);
  const [overridesText, setOverridesText] = useState("{}");
  const [testForm, setTestForm] = useState({ method: "GET", url: "https://example.test/", host: "example.test" });
  const [testResult, setTestResult] = useState(null);
  const [saveError, setSaveError] = useState("");
  const state = useAsync(() => api("/api/host-profiles"), [refreshKey]);

  useEffect(() => {
    const profile = (state.data || []).find((item) => item.id === selectedID);
    if (profile) {
      setForm(profile);
      setOverridesText(JSON.stringify(profile.overrides || {}, null, 2));
    }
  }, [selectedID, state.data]);

  if (state.loading || state.error) return <PageState state={state} />;
  const profiles = Array.isArray(state.data) ? state.data : [];
  const save = async () => {
    setSaveError("");
    try {
      const payload = { ...form, overrides: parseJSONEditorValue(overridesText, {}) };
      if (selectedID) await putJSON(`/api/host-profiles/${encodeURIComponent(selectedID)}`, payload);
      else {
        const created = await postJSON("/api/host-profiles", payload);
        setSelectedID(created.id);
      }
      refresh();
    } catch (err) {
      setSaveError(err.message);
    }
  };
  return (
    <div className="workbench">
      <aside className="workbench-sidebar">
        <div className="workbench-head"><div><h2>Host Profiles</h2><p>Per-host runtime overrides.</p></div><button className="secondary" onClick={() => { setSelectedID(""); setForm(emptyProfile); setOverridesText("{}"); }}><Plus />New</button></div>
        <div className="workbench-list">{profiles.length ? profiles.map((profile) => <button key={profile.id} className={`list-row ${profile.id === selectedID ? "active" : ""}`} onClick={() => setSelectedID(profile.id)}><div className="list-row-title"><Server /><span>{profile.name}</span></div><div className="list-row-meta">priority {profile.priority} - {profile.enabled ? "enabled" : "disabled"}</div></button>) : <EmptyList>No host profiles yet.</EmptyList>}</div>
      </aside>
      <section className="workbench-main">
        <div className="detail-shell">
          <div className="detail-topbar"><div><h2>{selectedID ? "Edit Host Profile" : "New Host Profile"}</h2></div><div className="detail-actions"><button className="primary" onClick={save}><Save />Save</button>{selectedID && <button className="secondary danger-button" onClick={async () => { await del(`/api/host-profiles/${encodeURIComponent(selectedID)}`); setSelectedID(""); setForm(emptyProfile); refresh(); }}><Trash2 />Delete</button>}</div></div>
          {saveError && <p className="error-text">{saveError}</p>}
          <div className="settings-grid">
            <label>Name<input value={form.name || ""} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
            <label>Priority<input type="number" value={form.priority || 100} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} /></label>
            <label><input type="checkbox" checked={form.enabled !== false} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} /> Enabled</label>
          </div>
          <div className="split-grid">
            <PatternEditor title="Hosts" placeholder={"example.com\n*.example.com"} values={form.host_patterns || []} onChange={(values) => setForm({ ...form, host_patterns: values })} />
            <PatternEditor title="URLs" placeholder={"*/api/*"} values={form.url_patterns || []} onChange={(values) => setForm({ ...form, url_patterns: values })} />
            <PatternEditor title="Methods" placeholder={"GET\nPOST"} values={form.method_patterns || []} onChange={(values) => setForm({ ...form, method_patterns: values })} />
            <JsonEditor title="Overrides JSON" value={overridesText} onChange={setOverridesText} minHeight={280} />
          </div>
          <p className="muted">Example overrides: {"{\"enable_mitm\":false,\"enable_faults\":false,\"verbose_logging\":true,\"blocked_domains\":[\"*.tracking.test\"]}"}</p>
        </div>
        <div className="detail-shell">
          <h2>Matcher Test</h2>
          <div className="settings-grid">
            <label>Method<input value={testForm.method} onChange={(e) => setTestForm({ ...testForm, method: e.target.value })} /></label>
            <label>URL<input value={testForm.url} onChange={(e) => setTestForm({ ...testForm, url: e.target.value })} /></label>
            <label>Host<input value={testForm.host} onChange={(e) => setTestForm({ ...testForm, host: e.target.value })} /></label>
          </div>
          <button className="secondary" onClick={async () => setTestResult(await postJSON("/api/host-profiles/test", testForm))}>Test Profile</button>
          <pre>{testResult ? JSON.stringify(testResult, null, 2) : ""}</pre>
        </div>
      </section>
    </div>
  );
}

function CertificatesView({ refreshKey, refresh }) {
  const state = useAsync(() => api("/api/certificates/ca"), [refreshKey]);
  const [paths, setPaths] = useState({ cert_path: "", key_path: "" });
  const [search, setSearch] = useState("");
  const [leaf, setLeaf] = useState([]);
  const [leafTotal, setLeafTotal] = useState(0);
  const [leafHasMore, setLeafHasMore] = useState(false);
  const [leafLoading, setLeafLoading] = useState(true);
  const [leafLoadingMore, setLeafLoadingMore] = useState(false);
  const [leafError, setLeafError] = useState("");
  const leafRequestRef = useRef(0);
  const pageSize = 10;

  const leafPagePath = (offset, term = search) => {
    const params = new URLSearchParams({ limit: String(pageSize), offset: String(offset) });
    if (term.trim()) params.set("q", term.trim());
    return `/api/certificates/leaf?${params.toString()}`;
  };

  const loadLeafPage = async (offset, replace = false, term = search) => {
    const requestID = ++leafRequestRef.current;
    replace ? setLeafLoading(true) : setLeafLoadingMore(true);
    setLeafError("");
    try {
      const page = await api(leafPagePath(offset, term));
      if (requestID !== leafRequestRef.current) return;
      const nextItems = page.items || [];
      setLeaf((current) => replace ? nextItems : [...current, ...nextItems]);
      setLeafTotal(page.total || 0);
      setLeafHasMore(Boolean(page.has_more));
    } catch (err) {
      if (requestID === leafRequestRef.current) setLeafError(err.message);
    } finally {
      if (requestID === leafRequestRef.current) {
        setLeafLoading(false);
        setLeafLoadingMore(false);
      }
    }
  };

  useEffect(() => {
    setLeaf([]);
    setLeafHasMore(false);
    loadLeafPage(0, true, search);
  }, [refreshKey, search]);

  if (state.loading || state.error) return <PageState state={state} />;
  const ca = state.data;
  return (
    <div className="page-stack">
      <PageTitle title="Certificates" subtitle="CA trust material and generated leaf certificates." />
      <div className="grid metrics-grid"><Metric label="Subject" value={ca.subject} /><Metric label="Expires" value={ca.expires_at} /><Metric label="Path" value={ca.path} /></div>
      <div className="panel"><h2>Fingerprint</h2><code>{ca.fingerprint}</code><div className="actions"><a className="primary" href={`/api/certificates/ca/download?token=${encodeURIComponent(getToken())}`}><Download />Download CA</a><button className="secondary" onClick={async () => { await post("/api/certificates/ca/rotate"); refresh(); }}><RefreshCw />Rotate CA</button></div><div className="actions"><input placeholder="cert path" value={paths.cert_path} onChange={(e) => setPaths({ ...paths, cert_path: e.target.value })} /><input placeholder="key path" value={paths.key_path} onChange={(e) => setPaths({ ...paths, key_path: e.target.value })} /><button className="secondary" onClick={async () => { await postJSON("/api/certificates/ca/import", paths); refresh(); }}>Import CA</button></div></div>
      <div className="panel"><h2>Trust Instructions</h2><table><tbody><tr><td>Windows</td><td>Import into Trusted Root Certification Authorities.</td></tr><tr><td>macOS</td><td>Import into Keychain Access and set Always Trust.</td></tr><tr><td>Linux</td><td>Install into the system CA store or browser-specific store.</td></tr><tr><td>Firefox</td><td>Import under Privacy & Security, Certificates, Authorities.</td></tr></tbody></table></div>
      <div className="panel"><div className="detail-topbar"><div><h2>Leaf Certificates</h2><p className="muted">Showing {leaf.length} of {leafTotal} matching certificates.</p></div><div className="list-filter"><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search host, subject, fingerprint..." /></div></div>{leafError && <p className="error-text">{leafError}</p>}<table><thead><tr><th>Host</th><th>Subject</th><th>Expires</th><th>Fingerprint</th></tr></thead><tbody>{leaf.length ? leaf.map((cert) => <tr key={cert.id || cert.host}><td>{cert.host}</td><td>{cert.subject}</td><td>{cert.expires_at}</td><td><code>{cert.fingerprint}</code></td></tr>) : <tr><td colSpan="4">{leafLoading ? "Loading certificates..." : "No leaf certificates found."}</td></tr>}</tbody></table><div className="list-status">{leafLoading && leaf.length > 0 ? "Refreshing..." : leafLoadingMore ? "Loading more..." : leafHasMore ? <button className="secondary" onClick={() => loadLeafPage(leaf.length)}>Load 10 more</button> : leaf.length ? "End of certificates." : ""}</div></div>
    </div>
  );
}

function AccessControlView({ refreshKey, refresh }) {
  const state = useAsync(async () => {
    const [users, rules] = await Promise.all([api("/api/proxy-auth/users"), api("/api/proxy-acl/rules")]);
    return { users, rules };
  }, [refreshKey]);
  const [userForm, setUserForm] = useState({ username: "", password: "", enabled: true });
  const emptyRule = { priority: 100, enabled: true, action: "deny", name: "", description: "", users: [], source_ips: [], host_patterns: [], port_patterns: [], method_patterns: [], scope_ids: [] };
  const [ruleForm, setRuleForm] = useState(emptyRule);
  const [selectedRuleID, setSelectedRuleID] = useState("");
  const [passwords, setPasswords] = useState({});
  const [testForm, setTestForm] = useState({ username: "", remote_ip: "127.0.0.1", method: "GET", url: "https://example.com/", scope_id: "" });
  const [testResult, setTestResult] = useState(null);
  useEffect(() => {
    const rule = (state.data?.rules || []).find((item) => item.id === selectedRuleID);
    if (rule) setRuleForm(rule);
  }, [selectedRuleID, state.data]);
  if (state.loading || state.error) return <PageState state={state} />;
  const { users, rules } = state.data;
  const saveRule = async () => {
    if (selectedRuleID) await putJSON(`/api/proxy-acl/rules/${encodeURIComponent(selectedRuleID)}`, ruleForm);
    else {
      const created = await postJSON("/api/proxy-acl/rules", ruleForm);
      setSelectedRuleID(created.id);
    }
    refresh();
  };
  return <div className="page-stack">
    <PageTitle title="Access Control" subtitle="Proxy users, authentication, and ordered allow/deny rules." />
    <div className="split-grid">
      <div className="panel">
        <h2>Proxy Users</h2>
        <div className="settings-grid">
          <label>Username<input value={userForm.username} onChange={(e) => setUserForm({ ...userForm, username: e.target.value })} /></label>
          <label>Password<input type="password" value={userForm.password} onChange={(e) => setUserForm({ ...userForm, password: e.target.value })} /></label>
          <label><input type="checkbox" checked={userForm.enabled} onChange={(e) => setUserForm({ ...userForm, enabled: e.target.checked })} /> Enabled</label>
        </div>
        <button className="secondary" onClick={async () => { await postJSON("/api/proxy-auth/users", userForm); setUserForm({ username: "", password: "", enabled: true }); refresh(); }}><Plus />Add User</button>
        <table><thead><tr><th>User</th><th>Enabled</th><th>Last used</th><th>Reset</th><th /></tr></thead><tbody>{users.map((user) => <tr key={user.id}><td>{user.username}</td><td><input type="checkbox" checked={!!user.enabled} onChange={async (e) => { await putJSON(`/api/proxy-auth/users/${user.id}`, { username: user.username, enabled: e.target.checked }); refresh(); }} /></td><td>{user.last_used_at || ""}</td><td><input type="password" className="compact-input" value={passwords[user.id] || ""} onChange={(e) => setPasswords({ ...passwords, [user.id]: e.target.value })} placeholder="new password" /></td><td><button className="rowbutton" onClick={async () => { await postJSON(`/api/proxy-auth/users/${user.id}/reset-password`, { password: passwords[user.id] || "" }); setPasswords({ ...passwords, [user.id]: "" }); refresh(); }}>Reset</button> <button className="rowbutton" onClick={async () => { await del(`/api/proxy-auth/users/${user.id}`); refresh(); }}>Delete</button></td></tr>)}</tbody></table>
      </div>
      <div className="panel">
        <h2>ACL Test</h2>
        <div className="settings-grid">
          <label>User<input value={testForm.username} onChange={(e) => setTestForm({ ...testForm, username: e.target.value })} /></label>
          <label>Source IP<input value={testForm.remote_ip} onChange={(e) => setTestForm({ ...testForm, remote_ip: e.target.value })} /></label>
          <label>Method<input value={testForm.method} onChange={(e) => setTestForm({ ...testForm, method: e.target.value })} /></label>
          <label>URL<input value={testForm.url} onChange={(e) => setTestForm({ ...testForm, url: e.target.value })} /></label>
          <label>Scope ID<input value={testForm.scope_id} onChange={(e) => setTestForm({ ...testForm, scope_id: e.target.value })} /></label>
        </div>
        <button className="secondary" onClick={async () => setTestResult(await postJSON("/api/proxy-acl/test", testForm))}>Test Rule</button>
        {testResult && <CodeCard title="ACL Test Result" value={testResult} />}
      </div>
    </div>
    <div className="workbench">
      <aside className="workbench-sidebar">
        <div className="workbench-head"><div><h2>ACL Rules</h2><p>First enabled match by priority wins.</p></div><button className="secondary" onClick={() => { setSelectedRuleID(""); setRuleForm(emptyRule); }}><Plus />New</button></div>
        <div className="workbench-list">{rules.length ? rules.map((rule) => <button key={rule.id} className={`list-row ${rule.id === selectedRuleID ? "active" : ""}`} onClick={() => setSelectedRuleID(rule.id)}><div className="list-row-title"><span className={`badge ${rule.action === "allow" ? "allow" : "block"}`}>{rule.action}</span><span>{rule.name}</span></div><div className="list-row-meta">priority {rule.priority} - {rule.enabled ? "enabled" : "disabled"}</div></button>) : <EmptyList>No ACL rules yet.</EmptyList>}</div>
      </aside>
      <section className="workbench-main">
        <div className="detail-shell">
          <div className="detail-topbar"><div className="detail-title"><h2>{selectedRuleID ? "Edit ACL Rule" : "New ACL Rule"}</h2></div><div className="detail-actions"><button className="primary" onClick={saveRule}><Save />Save</button>{selectedRuleID && <button className="secondary danger-button" onClick={async () => { await del(`/api/proxy-acl/rules/${selectedRuleID}`); setSelectedRuleID(""); setRuleForm(emptyRule); refresh(); }}><Trash2 />Delete</button>}</div></div>
          <div className="settings-grid">
            <label>Name<input value={ruleForm.name || ""} onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })} /></label>
            <label>Priority<input type="number" value={ruleForm.priority || 100} onChange={(e) => setRuleForm({ ...ruleForm, priority: Number(e.target.value) })} /></label>
            <label>Action<select value={ruleForm.action || "deny"} onChange={(e) => setRuleForm({ ...ruleForm, action: e.target.value })}><option value="allow">allow</option><option value="deny">deny</option></select></label>
            <label><input type="checkbox" checked={ruleForm.enabled !== false} onChange={(e) => setRuleForm({ ...ruleForm, enabled: e.target.checked })} /> Enabled</label>
          </div>
          <label className="stacked-label">Description<textarea value={ruleForm.description || ""} onChange={(e) => setRuleForm({ ...ruleForm, description: e.target.value })} /></label>
          <div className="split-grid">
            <PatternEditor title="Users" placeholder={"alice\nbob"} values={ruleForm.users || []} onChange={(values) => setRuleForm({ ...ruleForm, users: values })} />
            <PatternEditor title="Source IPs" placeholder={"127.0.0.1\n10.0.0.0/8"} values={ruleForm.source_ips || []} onChange={(values) => setRuleForm({ ...ruleForm, source_ips: values })} />
            <PatternEditor title="Hosts" placeholder={"example.com\n*.example.com"} values={ruleForm.host_patterns || []} onChange={(values) => setRuleForm({ ...ruleForm, host_patterns: values })} />
            <PatternEditor title="Ports" placeholder={"443\n8000-8999"} values={ruleForm.port_patterns || []} onChange={(values) => setRuleForm({ ...ruleForm, port_patterns: values })} />
            <PatternEditor title="Methods" placeholder={"GET\nPOST"} values={ruleForm.method_patterns || []} onChange={(values) => setRuleForm({ ...ruleForm, method_patterns: values })} />
            <PatternEditor title="Scope IDs" placeholder={"scope-id\n__out_of_scope__"} values={ruleForm.scope_ids || []} onChange={(values) => setRuleForm({ ...ruleForm, scope_ids: values })} />
          </div>
        </div>
      </section>
    </div>
  </div>;
}

function BlocksView({ refreshKey, refresh }) {
  const state = useAsync(async () => {
    const [ports, domains, ips] = await Promise.all([api("/api/blocks/ports"), api("/api/blocks/domains"), api("/api/blocks/ips")]);
    return { ports, domains, ips };
  }, [refreshKey]);
  const [form, setForm] = useState({ port: "", domain: "", ip: "", host: "", testPort: "", testIP: "" });
  const [testResult, setTestResult] = useState({});
  if (state.loading || state.error) return <PageState state={state} />;
  const { ports, domains, ips } = state.data;
  return (
    <div className="page-stack">
      <PageTitle title="Blocks" subtitle="Local deny rules and matcher verification." />
      <div className="grid metrics-grid"><Metric label="Ports" value={ports.length} /><Metric label="Domains" value={domains.length} /><Metric label="IPs" value={ips.length} /></div>
      <BlockPanel title="Ports" value={form.port} placeholder="25" setValue={(port) => setForm({ ...form, port })} add={async () => { await postJSON("/api/blocks/ports", { port: Number(form.port) }); refresh(); }} rows={ports.map((p) => [p, () => del(`/api/blocks/ports/${p}`).then(refresh)])} />
      <BlockPanel title="Domains" value={form.domain} placeholder="*.tracking.example" setValue={(domain) => setForm({ ...form, domain })} add={async () => { await postJSON("/api/blocks/domains", { pattern: form.domain }); refresh(); }} rows={domains.map((d) => [d, () => del(`/api/blocks/domains/${encodeURIComponent(d)}`).then(refresh)])} />
      <BlockPanel title="IPs" value={form.ip} placeholder="203.0.113.0/24" setValue={(ip) => setForm({ ...form, ip })} add={async () => { await postJSON("/api/blocks/ips", { pattern: form.ip }); refresh(); }} rows={ips.map((ip) => [ip, () => del(`/api/blocks/ips/${encodeURIComponent(ip)}`).then(refresh)])} />
      <div className="panel"><h2>Matcher Test</h2><div className="actions"><input placeholder="host" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} /><input type="number" placeholder="443" value={form.testPort} onChange={(e) => setForm({ ...form, testPort: e.target.value })} /><input placeholder="IP" value={form.testIP} onChange={(e) => setForm({ ...form, testIP: e.target.value })} /><button className="secondary" onClick={async () => setTestResult(await postJSON("/api/blocks/test", { host: form.host, port: Number(form.testPort), ip: form.testIP }))}>Test</button></div><pre>{JSON.stringify(testResult, null, 2)}</pre></div>
    </div>
  );
}

function BlockPanel({ title, value, placeholder, setValue, add, rows }) {
  return <div className="panel"><h2>{title}</h2><div className="actions"><input value={value} placeholder={placeholder} onChange={(e) => setValue(e.target.value)} /><button className="secondary" onClick={add}><Plus />Add</button></div><table><tbody>{rows.map(([label, remove]) => <tr key={label}><td>{label}</td><td><button className="rowbutton" onClick={remove}>Delete</button></td></tr>)}</tbody></table></div>;
}

function DeploymentsView({ refreshKey, refresh }) {
  const state = useAsync(async () => {
    const [deployment, logs] = await Promise.all([api("/api/deployments/current"), api("/api/logs")]);
    return { deployment, logs };
  }, [refreshKey]);
  const [restartState, setRestartState] = useState({ status: "idle", message: "" });
  if (state.loading || state.error) return <PageState state={state} />;
  const { deployment, logs } = state.data;
  const restarting = restartState.status === "pending";
  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const restart = async () => {
    const previousStarted = deployment.started_at || "";
    setRestartState({ status: "pending", message: "Restart requested. Waiting for the process to come back..." });
    try {
      await post("/api/deployments/current/restart");
    } catch (error) {
      setRestartState({ status: "error", message: `Restart request failed: ${error.message}` });
      return;
    }
    const deadline = Date.now() + 30000;
    let sawUnavailable = false;
    while (Date.now() < deadline) {
      await delay(900);
      try {
        const next = await api(`/api/deployments/current?restart_poll=${Date.now()}`);
        if (next.started_at && next.started_at !== previousStarted) {
          setRestartState({ status: "success", message: "Restart complete. The replacement process is responding." });
          refresh();
          return;
        }
        setRestartState({ status: "pending", message: sawUnavailable ? "Process is responding again; waiting for the new start time..." : "Restart accepted. Waiting for shutdown handoff..." });
      } catch {
        sawUnavailable = true;
        setRestartState({ status: "pending", message: "Process is temporarily unavailable during restart..." });
      }
    }
    setRestartState({ status: "error", message: "Restart status timed out. Refresh the page to check whether the process came back." });
  };
  return <div className="page-stack"><PageTitle title="Deployments" subtitle="Runtime controls, profiles, and recent log output." /><div className="grid metrics-grid"><Metric label="Status" value={deployment.status} /><Metric label="Listen address" value={deployment.listen_addr} /><Metric label="MITM" value={deployment.mitm_enabled ? "enabled" : "disabled"} /><Metric label="Config" value={deployment.config_path || "defaults"} /></div><div className="panel"><h2>Controls</h2><div className="actions"><button className="secondary" disabled={restarting} onClick={async () => { await post("/api/deployments/current/reload"); refresh(); }}><RefreshCw />Reload config</button><button className="secondary" disabled={restarting} onClick={restart}><RefreshCw />{restarting ? "Restarting..." : "Restart"}</button></div>{restartState.message && <div className={`restart-feedback ${restartState.status}`}>{restartState.message}</div>}</div><TextCard title="Logs" value={(logs || []).join("\n")} /><div className="panel"><h2>Profiles</h2><table><thead><tr><th>Name</th><th>Kind</th><th>Description</th></tr></thead><tbody>{(deployment.profiles || []).map((p) => <tr key={p.name}><td>{p.name}</td><td>{p.kind}</td><td>{p.description}</td></tr>)}</tbody></table></div></div>;
}

function CacheView({ refreshKey, refresh }) {
  const [domain, setDomain] = useState("");
  const [search, setSearch] = useState("");
  const [cache, setCache] = useState(null);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [hasMore, setHasMore] = useState(false);
  const [itemsTotal, setItemsTotal] = useState(0);
  const requestRef = useRef(0);
  const pageSize = 10;

  const cachePagePath = (offset, term = search) => {
    const params = new URLSearchParams({ limit: String(pageSize), offset: String(offset) });
    if (term.trim()) params.set("q", term.trim());
    return `/api/cache?${params.toString()}`;
  };

  const loadCachePage = async (offset, replace = false, term = search) => {
    const requestID = ++requestRef.current;
    replace ? setLoading(true) : setLoadingMore(true);
    setError("");
    try {
      const page = await api(cachePagePath(offset, term));
      if (requestID !== requestRef.current) return;
      setCache(page);
      setItems((current) => replace ? (page.items || []) : [...current, ...(page.items || [])]);
      setHasMore(Boolean(page.has_more));
      setItemsTotal(page.items_total || 0);
    } catch (err) {
      if (requestID === requestRef.current) setError(err.message);
    } finally {
      if (requestID === requestRef.current) {
        setLoading(false);
        setLoadingMore(false);
      }
    }
  };

  useEffect(() => {
    setHasMore(false);
    setItems([]);
    loadCachePage(0, true, search);
  }, [refreshKey, search]);

  if (!cache && loading) return <PageState state={{ loading: true }} />;
  if (!cache && error) return <PageState state={{ error }} />;

  return <div className="page-stack"><PageTitle title="Cache" subtitle="HTTP response cache inventory and purge controls." /><div className="grid metrics-grid"><Metric label="Enabled" value={cache.enabled ? "yes" : "no"} /><Metric label="Store" value={cache.directory} /><Metric label="TTL" value={`${cache.ttl}s`} /><Metric label="Entries" value={cache.entries} /><Metric label="Hit rate" value={`${cache.hits || 0}/${(cache.hits || 0) + (cache.misses || 0)}`} /><Metric label="Size" value={`${cache.size} bytes`} /></div><div className="panel"><h2>Purge</h2><div className="actions"><input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="optional domain" /><button className="secondary" onClick={async () => { await postJSON("/api/cache/purge", { domain }); setDomain(""); refresh(); }}>Purge</button></div></div><div className="panel"><div className="detail-topbar"><div><h2>Cached Entries</h2><p className="muted">Showing {items.length} of {itemsTotal} matching entries.</p></div><div className="list-filter"><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search URL, key, status, size..." /></div></div>{error && <p className="error-text">{error}</p>}<table><thead><tr><th>URL</th><th>Status</th><th>Expires</th><th>Size</th></tr></thead><tbody>{items.length ? items.map((i) => <tr key={i.key || i.url}><td><a className="cache-link" href={authenticatedHref(i.view_url || `/api/cache/resource?key=${encodeURIComponent(i.key || "")}`)} target="_blank" rel="noreferrer">{i.url || i.key}</a></td><td>{i.status}</td><td>{i.expires_at}</td><td>{i.size || 0}</td></tr>) : <tr><td colSpan="4">{loading ? "Loading cached entries..." : "No cached entries found."}</td></tr>}</tbody></table><div className="list-status">{loading && items.length > 0 ? "Refreshing..." : loadingMore ? "Loading more..." : hasMore ? <button className="secondary" onClick={() => loadCachePage(items.length)}>Load 10 more</button> : items.length ? "End of cached entries." : ""}</div></div></div>;
}

function ScopesView({ scopes, refresh, setSelectedScope }) {
  const [selectedID, setSelectedID] = useState(scopes[0]?.id || "");
  const selected = scopes.find((scope) => scope.id === selectedID);
  const emptyForm = { name: "", description: "", enabled: true, host_patterns: [], url_patterns: [], method_patterns: [] };
  const [form, setForm] = useState(emptyForm);

  useEffect(() => {
    if (selected) {
      setForm({
        name: selected.name || "",
        description: selected.description || "",
        enabled: selected.enabled !== false,
        host_patterns: selected.host_patterns || [],
        url_patterns: selected.url_patterns || [],
        method_patterns: selected.method_patterns || [],
      });
    } else {
      setForm(emptyForm);
    }
  }, [selectedID, scopes]);

  const payload = () => ({
    ...form,
    host_patterns: form.host_patterns,
    url_patterns: form.url_patterns,
    method_patterns: form.method_patterns,
  });
  const save = async () => {
    if (selected) {
      await putJSON(`/api/scopes/${selected.id}`, payload());
    } else {
      const created = await postJSON("/api/scopes", payload());
      setSelectedID(created.id);
      setSelectedScope(created.id);
    }
    refresh();
  };

  return (
    <div className="workbench">
      <aside className="workbench-sidebar">
        <div className="workbench-head">
          <div>
            <h2>Scopes</h2>
            <p>Target boundaries for focused research.</p>
          </div>
          <div className="actions"><button className="secondary" onClick={() => { setSelectedID(""); setForm(emptyForm); }}><Plus />New</button></div>
        </div>
        <div className="workbench-list">
          {scopes.length ? scopes.map((scope) => (
            <button key={scope.id} className={`list-row ${scope.id === selectedID ? "active" : ""}`} onClick={() => setSelectedID(scope.id)}>
              <div className="list-row-title"><ScopeBadge scopeID={scope.id} scopes={scopes} /><span>{scope.name}</span></div>
              <div className="list-row-meta">{scope.enabled ? "enabled" : "disabled"} - {(scope.host_patterns || []).length + (scope.url_patterns || []).length + (scope.method_patterns || []).length} patterns</div>
              <div className="list-row-meta">{scope.updated_at || ""}</div>
            </button>
          )) : <EmptyList>No scopes yet.</EmptyList>}
        </div>
      </aside>
      <section className="workbench-main">
        <div className="detail-shell">
          <div className="detail-topbar">
            <div className="detail-title"><h2>{selected ? "Edit Scope" : "New Scope"}</h2><p className="muted">Use host, URL, and method patterns to classify future traffic.</p></div>
            <div className="detail-actions">
              <button className="primary" onClick={save}><Save />Save</button>
              {selected && <button className="secondary danger-button" onClick={async () => { if (!confirm("Delete this scope? Related data will remain unscoped.")) return; await del(`/api/scopes/${selected.id}`); setSelectedScope("all"); setSelectedID(""); refresh(); }}><Trash2 />Delete</button>}
            </div>
          </div>
          <div className="editor-stack">
            <label>Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
            <label>Description<textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></label>
            <label><input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} /> Enabled</label>
            <div className="split-grid">
              <PatternEditor title="Host Patterns" placeholder={"example.com\n*.example.com"} values={form.host_patterns} onChange={(values) => setForm({ ...form, host_patterns: values })} />
              <PatternEditor title="URL Patterns" placeholder={"/api/\ntoken="} values={form.url_patterns} onChange={(values) => setForm({ ...form, url_patterns: values })} />
            </div>
            <PatternEditor title="Method Patterns" placeholder={"GET\nPOST"} values={form.method_patterns} onChange={(values) => setForm({ ...form, method_patterns: values })} />
          </div>
        </div>
      </section>
    </div>
  );
}

function PatternEditor({ title, placeholder, values, onChange }) {
  const serializedValues = (values || []).join("\n");
  const [text, setText] = useState(serializedValues);

  useEffect(() => {
    setText(serializedValues);
  }, [serializedValues]);

  return (
    <div className="section-card">
      <h3>{title}</h3>
      <textarea
        placeholder={placeholder}
        value={text}
        onChange={(e) => {
          const next = e.target.value;
          setText(next);
          onChange(next.split("\n").map((value) => value.trim()).filter(Boolean));
        }}
      />
    </div>
  );
}

function SettingsView({ refreshKey, refresh }) {
  const state = useAsync(() => api("/api/settings"), [refreshKey]);
  const [form, setForm] = useState(null);
  const [saveError, setSaveError] = useState("");
  useEffect(() => { if (state.data) setForm(state.data); }, [state.data]);
  if (state.loading || state.error || !form) return <PageState state={state} />;
  const capture = form.traffic_capture || {};
  const aiCopilot = form.ai_copilot || {};
  const upstreamProxy = form.upstream_proxy || {};
  const proxyAuth = form.proxy_auth || {};
  const intercept = form.intercept || {};
  const set = (patch) => setForm((prev) => ({ ...prev, ...patch }));
  const setCapture = (patch) => set({ traffic_capture: { ...capture, ...patch } });
  const setAICopilot = (patch) => set({ ai_copilot: { ...aiCopilot, ...patch } });
  const setUpstreamProxy = (patch) => set({ upstream_proxy: { ...upstreamProxy, ...patch } });
  const setProxyAuth = (patch) => set({ proxy_auth: { ...proxyAuth, ...patch } });
  const setIntercept = (patch) => set({ intercept: { ...intercept, ...patch } });
  const danger = async (action, message) => {
    if (!confirm(message)) return;
    await postJSON("/api/settings/danger", { action, confirm: true });
    refresh();
  };
  return (
    <div className="page-stack">
      <PageTitle title="Settings" subtitle="Runtime behavior and capture policy." />
      <div className="panel">
        <div className="detail-topbar">
          <h2>Settings</h2>
          <button className="primary" onClick={async () => { setSaveError(""); try { await putJSON("/api/settings", form); refresh(); } catch (err) { setSaveError(err.message); } }}><Save />Save</button>
        </div>
        {saveError && <p className="error-text">{saveError}</p>}
        <h3>Runtime</h3>
        <div className="settings-grid">
          <label><input type="checkbox" checked={!!form.enable_mitm} onChange={(e) => set({ enable_mitm: e.target.checked })} /> Enable MITM</label>
          <label><input type="checkbox" checked={!!form.verbose_logging} onChange={(e) => set({ verbose_logging: e.target.checked })} /> Verbose logging</label>
          <label><input type="checkbox" checked={!!form.log_requests} onChange={(e) => set({ log_requests: e.target.checked })} /> Request logging</label>
          <label>TLS minimum<input value={form.min_tls_version || ""} onChange={(e) => set({ min_tls_version: e.target.value })} /></label>
          <label>Idle timeout<input type="number" value={form.idle_timeout_seconds || 0} onChange={(e) => set({ idle_timeout_seconds: Number(e.target.value) })} /></label>
        </div>
        <h3>Traffic Capture</h3>
        <div className="settings-grid">
          <label><input type="checkbox" checked={!!capture.store_bodies} onChange={(e) => setCapture({ store_bodies: e.target.checked })} /> Store body samples</label>
          <label><input type="checkbox" checked={capture.redact_bodies !== false} onChange={(e) => setCapture({ redact_bodies: e.target.checked })} /> Redact body samples</label>
          <label><input type="checkbox" checked={capture.store_headers !== false} onChange={(e) => setCapture({ store_headers: e.target.checked })} /> Store headers</label>
          <label><input type="checkbox" checked={capture.store_cookies !== false} onChange={(e) => setCapture({ store_cookies: e.target.checked })} /> Store cookies</label>
          <label>Max body bytes<input type="number" value={capture.max_body_bytes || 32768} onChange={(e) => setCapture({ max_body_bytes: Number(e.target.value) })} /></label>
        </div>
        <div className="split-grid">
          <PatternEditor title="Redacted Headers" placeholder={"Authorization\nCookie\nSet-Cookie\nX-Api-Key"} values={capture.redacted_headers || []} onChange={(values) => setCapture({ redacted_headers: values })} />
          <PatternEditor title="Redacted Cookies" placeholder={"session\ncsrf_token"} values={capture.redacted_cookies || []} onChange={(values) => setCapture({ redacted_cookies: values })} />
        </div>
        <h3>AI Copilot</h3>
        <div className="settings-grid">
          <label><input type="checkbox" checked={!!aiCopilot.enabled} onChange={(e) => setAICopilot({ enabled: e.target.checked })} /> Enable AI Copilot</label>
          <label>Provider<input value={aiCopilot.provider || "openai"} onChange={(e) => setAICopilot({ provider: e.target.value })} /></label>
          <label>Model<input value={aiCopilot.model || ""} onChange={(e) => setAICopilot({ model: e.target.value })} /></label>
          <label>Timeout ms<input type="number" value={aiCopilot.timeout_ms || 10000} onChange={(e) => setAICopilot({ timeout_ms: Number(e.target.value) })} /></label>
          <label>Max body bytes<input type="number" value={aiCopilot.max_body_bytes || 32768} onChange={(e) => setAICopilot({ max_body_bytes: Number(e.target.value) })} /></label>
          <label>API key env var<input value={aiCopilot.openai_api_key_env || "OPENAI_API_KEY"} onChange={(e) => setAICopilot({ openai_api_key_env: e.target.value })} /></label>
          <label><input type="checkbox" checked={aiCopilot.redact_before_ai !== false} onChange={(e) => setAICopilot({ redact_before_ai: e.target.checked })} /> Redact before AI</label>
        </div>
        <p className="muted">API keys are read from the proxy process environment and are never stored in dashboard settings.</p>
        <h3>Upstream Proxy</h3>
        <div className="settings-grid">
          <label><input type="checkbox" checked={!!upstreamProxy.enabled} onChange={(e) => setUpstreamProxy({ enabled: e.target.checked })} /> Enable upstream chaining</label>
          <label>Proxy URL<input value={upstreamProxy.url || ""} placeholder="http://127.0.0.1:8080" onChange={(e) => setUpstreamProxy({ url: e.target.value })} /></label>
          <label>Username<input value={upstreamProxy.username || ""} placeholder={upstreamProxy.has_username ? "configured; enter a new username to replace" : "optional Basic auth username"} onChange={(e) => setUpstreamProxy({ username: e.target.value })} /></label>
          <label>Password env var<input value={upstreamProxy.password_env || "UPSTREAM_PROXY_PASSWORD"} onChange={(e) => setUpstreamProxy({ password_env: e.target.value })} /></label>
          <label><input type="checkbox" checked={upstreamProxy.chain_tunnels !== false} onChange={(e) => setUpstreamProxy({ chain_tunnels: e.target.checked })} /> Chain CONNECT and WebSocket tunnels</label>
          <label><input type="checkbox" checked={upstreamProxy.apply_to_repeater !== false} onChange={(e) => setUpstreamProxy({ apply_to_repeater: e.target.checked })} /> Apply to Repeater sends</label>
        </div>
        <label className="stacked-label">Bypass hosts<textarea placeholder={"localhost\n127.0.0.1\n*.internal"} value={(upstreamProxy.no_proxy || []).join("\n")} onChange={(e) => setUpstreamProxy({ no_proxy: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean) })} /></label>
        <p className="muted">HTTP and HTTPS upstream proxies are supported. Passwords are read from the proxy process environment and are never stored in dashboard settings.</p>
        <h3>Proxy Authentication</h3>
        <div className="settings-grid">
          <label><input type="checkbox" checked={!!proxyAuth.enabled} onChange={(e) => setProxyAuth({ enabled: e.target.checked, default_action: e.target.checked ? "deny" : (proxyAuth.default_action || "allow") })} /> Require proxy authentication</label>
          <label>Realm<input value={proxyAuth.realm || "MITM Proxy"} onChange={(e) => setProxyAuth({ realm: e.target.value })} /></label>
          <label>Default action<select value={proxyAuth.default_action || "allow"} onChange={(e) => setProxyAuth({ default_action: e.target.value })}><option value="allow">allow</option><option value="deny">deny</option></select></label>
          <label><input type="checkbox" checked={!!proxyAuth.require_auth_for_loopback} onChange={(e) => setProxyAuth({ require_auth_for_loopback: e.target.checked })} /> Require auth for loopback clients</label>
        </div>
        <p className="muted">Manage proxy users and ordered ACL rules in Access Control. Passwords are hashed before storage.</p>
        <h3>Intercept</h3>
        <div className="settings-grid">
          <label><input type="checkbox" checked={!!intercept.enabled} onChange={(e) => setIntercept({ enabled: e.target.checked })} /> Enable breakpoints</label>
          <label>Timeout ms<input type="number" value={intercept.timeout_ms || 30000} onChange={(e) => setIntercept({ timeout_ms: Number(e.target.value) })} /></label>
          <label>Timeout action<select value={intercept.timeout_action || "forward"} onChange={(e) => setIntercept({ timeout_action: e.target.value })}><option value="forward">forward</option><option value="drop">drop</option></select></label>
        </div>
        <h3>Excluded Domains</h3>
        <textarea value={(form.excluded_domains || []).join("\n")} onChange={(e) => set({ excluded_domains: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean) })} />
        <CodeCard title="Cache" value={form.cache || {}} />
      </div>
      <div className="panel danger-zone">
        <div className="detail-topbar"><div><h2>Dangerous</h2><p className="muted">Destructive maintenance actions. Each action requires confirmation.</p></div></div>
        <div className="actions">
          <button className="secondary danger-button" onClick={() => danger("all", "Purge all stored dashboard research data, cache, proxy users, and ACL rules? This cannot be undone.")}><Trash2 />Purge All Data</button>
          <button className="secondary danger-button" onClick={() => danger("except_cache", "Purge all stored dashboard research data except cache? This cannot be undone.")}><Trash2 />Purge All Except Cache</button>
          <button className="secondary danger-button" onClick={() => danger("cache", "Purge all cached responses? This cannot be undone.")}><Trash2 />Purge Cache</button>
        </div>
      </div>
    </div>
  );
}

function AuditLogView({ refreshKey }) {
  const state = useAsync(() => api("/api/audit"), [refreshKey]);
  if (state.loading || state.error) return <PageState state={state} />;
  return <div className="page-stack"><PageTitle title="Audit Log" subtitle="Administrative activity and system events." /><div className="panel"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>{state.data.map((e) => <tr key={`${e.created_at}-${e.action}`}><td>{e.created_at}</td><td>{e.actor}</td><td>{e.action}</td><td><code>{e.details ? JSON.stringify(e.details) : ""}</code></td></tr>)}</tbody></table></div></div>;
}

function ThreatScannerView({ refreshKey, refresh, selectedScope, scopes }) {
  const state = useAsync(() => api(`/api/threats/events${scopeQuery(selectedScope)}`), [refreshKey, selectedScope]);
  const [detail, setDetail] = useState(null);
  if (state.loading || state.error) return <PageState state={state} />;
  const data = state.data;
  const m = data.metrics;
  return <div className="page-stack"><PageTitle title="Threat Scanner" subtitle="Detection stream, verdicts, and rule activity." /><div className="grid metrics-grid"><Metric label="Scanned requests" value={m.scanned_requests} /><Metric label="Scanned responses" value={m.scanned_responses} /><Metric label="Warnings" value={m.warnings} /><Metric label="Blocked threats" value={m.blocked_threats} /><Metric label="Quarantine" value={m.quarantined} /><Metric label="AI calls" value={m.ai_calls} /><Metric label="Average latency" value={`${Number(m.average_scan_latency_ms).toFixed(1)} ms`} /><Metric label="Timeouts" value={m.timeouts} /></div><div className="panel"><h2>Live Detections</h2><table><thead><tr><th>Time</th><th>Target</th><th>Host</th><th>Scope</th><th>Action</th><th>Score</th><th>AI</th><th>Reason</th></tr></thead><tbody>{(data.events || []).map((e) => <tr key={e.id}><td>{e.timestamp}</td><td>{e.target}</td><td>{e.host || ""}</td><td><ScopeBadge scopeID={e.scope_id} scopes={scopes} /></td><td><span className={`badge ${e.verdict.action}`}>{e.verdict.action}</span></td><td>{e.local_result ? e.local_result.score : ""}</td><td>{e.ai_used ? "yes" : "no"}</td><td><button className="rowbutton" onClick={async () => setDetail(await api(`/api/threats/events/${e.id}`))}>{e.verdict.reason}</button></td></tr>)}</tbody></table></div><div className="panel"><h2>Top Rules</h2><table><thead><tr><th>ID</th><th>Name</th><th>Hits</th><th>False positives</th></tr></thead><tbody>{(m.top_rules || []).map((r) => <tr key={r.id}><td><code>{r.id}</code></td><td>{r.name}</td><td>{r.hits}</td><td>{r.false_positive_overrides}</td></tr>)}</tbody></table></div>{detail ? <ThreatDetail event={detail} refresh={refresh} /> : <div className="panel"><h2>Detection Detail</h2><p>Select a detection reason to inspect signals, AI output, and redaction details.</p></div>}</div>;
}

function ThreatDetail({ event, refresh }) {
  const signals = ((event.local_result && event.local_result.signals) || []);
  const override = async (action) => { await post(`/api/threats/events/${event.id}/${action}`); refresh(); };
  return <div className="panel"><div className="detail-topbar"><h2>Detection Detail</h2><div className="actions"><button className="secondary" onClick={() => override("false-positive")}>Mark false positive</button><button className="secondary" onClick={() => override("allow")}>Allow</button><button className="secondary" onClick={() => override("block")}>Block</button><button className="secondary" onClick={() => override("quarantine")}>Quarantine</button></div></div><div className="grid metrics-grid compact"><Metric label="Final action" value={event.verdict.action} /><Metric label="Local score" value={event.local_result.score} /><Metric label="AI used" value={event.ai_used ? "yes" : "no"} /><Metric label="Latency" value={`${event.scan_latency_ms} ms`} /></div><h3>Signals</h3><table><thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Severity</th><th>Weight</th><th>Evidence</th></tr></thead><tbody>{signals.map((s) => <tr key={s.id}><td><code>{s.id}</code></td><td>{s.name}</td><td>{s.category}</td><td>{s.severity}</td><td>{s.weight}</td><td><code>{JSON.stringify(s.evidence || {})}</code></td></tr>)}</tbody></table><CodeCard title="AI Verdict" value={event.ai_verdict || {}} /><CodeCard title="Redaction" value={(event.evidence && event.evidence.redaction) || {}} /><CodeCard title="Quarantine" value={(event.evidence && event.evidence.quarantine) || {}} /></div>;
}

function PageTitle({ title, subtitle, actions }) {
  return <div className="page-title"><div><h1>{title}</h1><p>{subtitle}</p></div>{actions && <div className="page-actions">{actions}</div>}</div>;
}

function Metric({ label, value, tone, hint }) {
  return <div className={`metric ${tone ? `metric-${tone}` : ""}`}><span>{label}</span><strong>{value}{hint && <> <small>{hint}</small></>}</strong></div>;
}

function MethodPill({ method }) {
  const upper = String(method || "").toUpperCase();
  return <span className={`method-pill ${METHOD_CLASS[upper] || ""}`}>{upper}</span>;
}

function ScopeBadge({ scopeID, scopes }) {
  if (!scopeID) return <span className="scope-badge out">out of scope</span>;
  const scope = (scopes || []).find((item) => item.id === scopeID);
  return <span className="scope-badge">{scope ? scope.name : "scope"}</span>;
}

function ProxyUserBadge({ username }) {
  if (!username) return null;
  return <span className="scope-badge user">{username}</span>;
}

function EmptyList({ children }) {
  return <div className="empty-list">{children}</div>;
}

function EmptyDetail({ title, body }) {
  return <div className="detail-shell"><h2>{title}</h2><p className="muted">{body}</p></div>;
}

function HeaderTable({ title, rows }) {
  return <div className="section-card"><h3>{title}</h3><table className="kv-table"><tbody>{rows.length ? rows.map((h, idx) => <tr key={`${h.name}-${idx}`}><td>{h.name}</td><td><code>{h.value}</code></td></tr>) : <tr><td colSpan="2">No headers captured.</td></tr>}</tbody></table></div>;
}

function CodeCard({ title, value }) {
  return <div className="section-card"><h3>{title}</h3><pre>{JSON.stringify(value, null, 2)}</pre></div>;
}

function JsonEditor({ title, value, onChange, minHeight = 220 }) {
  const [error, setError] = useState("");
  const textareaRef = useRef(null);
  const lines = String(value || "").split("\n").length;
  const lineNumbers = Array.from({ length: Math.max(lines, 1) }, (_, index) => index + 1).join("\n");
  const update = (next) => {
    onChange(next);
    try {
      parseJSONEditorValue(next, {});
      setError("");
    } catch (err) {
      setError(err.message);
    }
  };
  const setValueAndSelection = (next, start, end = start) => {
    update(next);
    requestAnimationFrame(() => {
      const textarea = textareaRef.current;
      if (!textarea) return;
      textarea.selectionStart = start;
      textarea.selectionEnd = end;
    });
  };
  const insertAroundSelection = (open, close = open) => {
    const textarea = textareaRef.current;
    if (!textarea) return;
    const text = String(value || "");
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selected = text.slice(start, end);
    if (!selected && text[start] === close) {
      textarea.selectionStart = start + 1;
      textarea.selectionEnd = start + 1;
      return;
    }
    const next = text.slice(0, start) + open + selected + close + text.slice(end);
    if (selected) setValueAndSelection(next, start + 1, end + 1);
    else setValueAndSelection(next, start + 1);
  };
  const handleKeyDown = (event) => {
    const textarea = textareaRef.current;
    if (!textarea) return;
    const text = String(value || "");
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    if (event.key === "Tab") {
      event.preventDefault();
      const lineStart = text.lastIndexOf("\n", start - 1) + 1;
      const selectionEndLineBreak = text.indexOf("\n", end);
      const blockEnd = selectionEndLineBreak === -1 ? text.length : selectionEndLineBreak;
      const hasMultiLineSelection = text.slice(start, end).includes("\n");
      if (!hasMultiLineSelection) {
        if (event.shiftKey) {
          if (text.slice(lineStart, lineStart + 2) === "  ") {
            setValueAndSelection(text.slice(0, lineStart) + text.slice(lineStart + 2), Math.max(lineStart, start - 2), Math.max(lineStart, end - 2));
          }
          return;
        }
        setValueAndSelection(text.slice(0, start) + "  " + text.slice(end), start + 2);
        return;
      }
      const before = text.slice(0, lineStart);
      const block = text.slice(lineStart, blockEnd);
      const after = text.slice(blockEnd);
      const linesInBlock = block.split("\n");
      let deltaStart = 0;
      let deltaEnd = 0;
      const nextLines = linesInBlock.map((line, index) => {
        if (event.shiftKey) {
          if (line.startsWith("  ")) {
            if (index === 0 && start >= lineStart + 2) deltaStart -= 2;
            deltaEnd -= 2;
            return line.slice(2);
          }
          return line;
        }
        if (index === 0) deltaStart += 2;
        deltaEnd += 2;
        return "  " + line;
      });
      setValueAndSelection(before + nextLines.join("\n") + after, start + deltaStart, end + deltaEnd);
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      const lineStart = text.lastIndexOf("\n", start - 1) + 1;
      const currentLine = text.slice(lineStart, start);
      const baseIndent = currentLine.match(/^\s*/)?.[0] || "";
      const extraIndent = /[\{\[]\s*$/.test(currentLine) ? "  " : "";
      const nextChar = text[end] || "";
      if ((nextChar === "}" || nextChar === "]") && extraIndent) {
        const insert = "\n" + baseIndent + extraIndent + "\n" + baseIndent;
        setValueAndSelection(text.slice(0, start) + insert + text.slice(end), start + baseIndent.length + extraIndent.length + 1);
        return;
      }
      const insert = "\n" + baseIndent + extraIndent;
      setValueAndSelection(text.slice(0, start) + insert + text.slice(end), start + insert.length);
      return;
    }
    if ((event.key === "\"" || event.key === "'") && !event.metaKey && !event.ctrlKey && !event.altKey) {
      event.preventDefault();
      insertAroundSelection("\"", "\"");
      return;
    }
    const pairs = { "{": "}", "[": "]", "(": ")" };
    if (pairs[event.key] && !event.metaKey && !event.ctrlKey && !event.altKey) {
      event.preventDefault();
      insertAroundSelection(event.key, pairs[event.key]);
      return;
    }
    if ((event.key === "}" || event.key === "]" || event.key === ")") && text[start] === event.key && start === end) {
      event.preventDefault();
      textarea.selectionStart = start + 1;
      textarea.selectionEnd = start + 1;
      return;
    }
    if (event.key === "Backspace" && start === end && start > 0) {
      const prev = text[start - 1];
      const next = text[start];
      if ((prev === "\"" && next === "\"") || (prev === "{" && next === "}") || (prev === "[" && next === "]") || (prev === "(" && next === ")")) {
        event.preventDefault();
        setValueAndSelection(text.slice(0, start - 1) + text.slice(start + 1), start - 1);
      }
    }
  };
  const format = () => {
    try {
      const parsed = parseJSONEditorValue(value, {});
      const next = JSON.stringify(parsed, null, 2);
      onChange(next);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  };
  const compact = () => {
    try {
      const parsed = parseJSONEditorValue(value, {});
      const next = JSON.stringify(parsed);
      onChange(next);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  };
  return (
    <div className="section-card json-editor-card">
      <div className="json-editor-head">
        <h3>{title}</h3>
        <div className="actions">
          <button className="rowbutton" type="button" onClick={format}>Format</button>
          <button className="rowbutton" type="button" onClick={compact}>Compact</button>
        </div>
      </div>
      <div className={`json-editor ${error ? "invalid" : ""}`} style={{ minHeight }}>
        <pre className="json-editor-lines" aria-hidden="true">{lineNumbers}</pre>
        <textarea
          ref={textareaRef}
          spellCheck="false"
          value={value || ""}
          onChange={(e) => update(e.target.value)}
          onKeyDown={handleKeyDown}
          style={{ minHeight }}
        />
      </div>
      <div className={`json-editor-status ${error ? "error-text" : "muted"}`}>{error || "Valid JSON"}</div>
    </div>
  );
}

function TextCard({ title, value, onChange }) {
  if (onChange) {
    return <div className="section-card"><h3>{title}</h3><textarea value={value || ""} onChange={(e) => onChange(e.target.value)} /></div>;
  }
  return <div className="section-card"><h3>{title}</h3>{value ? <pre>{value}</pre> : <div className="empty-sample">No body sample captured.</div>}</div>;
}

createRoot(document.getElementById("root")).render(<App />);
