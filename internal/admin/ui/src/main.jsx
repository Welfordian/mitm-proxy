import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  Ban,
  Check,
  Database,
  Download,
  FileJson,
  LayoutDashboard,
  Play,
  Plus,
  RefreshCw,
  Repeat,
  Save,
  ScrollText,
  Send,
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
    ["Traffic", Activity],
    ["Repeater", Repeat],
    ["Threat Scanner", ShieldAlert],
    ["Certificates", ShieldCheck],
  ] },
  { group: "Operate", items: [
    ["Blocks", Ban],
    ["Deployments", Server],
    ["Cache", Database],
    ["Settings", Settings],
    ["Admin Users", Users],
    ["Audit Log", ScrollText],
  ] },
];

const METHOD_CLASS = {
  GET: "get",
  POST: "post",
  PUT: "put",
  PATCH: "patch",
  DELETE: "delete",
};

function getToken() {
  const value = new URLSearchParams(location.search).get("token") || localStorage.getItem("adminToken") || "";
  if (value) localStorage.setItem("adminToken", value);
  return value;
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const t = getToken();
  if (t) headers.Authorization = `Bearer ${t}`;
  const res = await fetch(path, { ...options, headers });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
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

function del(path) {
  return request(path, { method: "DELETE" });
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

function App() {
  const [current, setCurrent] = useState("Dashboard");
  const [refreshKey, setRefreshKey] = useState(0);
  const [status, setStatus] = useState("checking");
  const [confirmed, setConfirmed] = useState(localStorage.getItem("responsibleUseConfirmed") === "true");
  const refresh = () => setRefreshKey((v) => v + 1);

  const body = useMemo(() => {
    const props = { refreshKey, refresh, setCurrent };
    switch (current) {
      case "Traffic": return <TrafficView {...props} />;
      case "Repeater": return <RepeaterView {...props} />;
      case "Threat Scanner": return <ThreatScannerView {...props} />;
      case "Certificates": return <CertificatesView {...props} />;
      case "Blocks": return <BlocksView {...props} />;
      case "Deployments": return <DeploymentsView {...props} />;
      case "Cache": return <CacheView {...props} />;
      case "Settings": return <SettingsView {...props} />;
      case "Admin Users": return <AdminUsersView {...props} />;
      case "Audit Log": return <AuditLogView {...props} />;
      default: return <DashboardView refreshKey={refreshKey} setStatus={setStatus} />;
    }
  }, [current, refreshKey]);

  return (
    <>
      <header className="topbar">
        <div className="brand"><img className="brand-mark" src="./logo-mark.svg" alt="" aria-hidden="true" />MITM Proxy Admin</div>
        <span className="env-pill">research console</span>
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
  if (state.error) return <div className="panel error">Unable to load: <code>{state.error.message}</code></div>;
  return null;
}

function DashboardView({ refreshKey, setStatus }) {
  const state = useAsync(async () => {
    const [health, version] = await Promise.all([api("/api/health"), api("/api/version")]);
    return { health, version };
  }, [refreshKey]);

  useEffect(() => {
    if (state.data?.health?.status) setStatus(state.data.health.status);
  }, [state.data, setStatus]);

  if (state.loading || state.error) return <PageState state={state} />;
  const { health, version } = state.data;
  return (
    <div className="page-stack">
      <PageTitle title="Dashboard" subtitle="Live proxy posture and administrative runtime." />
      <div className="grid metrics-grid">
        <Metric label="Proxy" value={health.proxy.listen_addr} />
        <Metric label="MITM" value={health.proxy.mitm_enabled ? "enabled" : "disabled"} />
        <Metric label="Admin" value={health.admin.addr} />
        <Metric label="Version" value={version.version} />
      </div>
    </div>
  );
}

function TrafficView({ refreshKey, refresh, setCurrent }) {
  const [selected, setSelected] = useState("");
  const [detail, setDetail] = useState(null);
  const [detailError, setDetailError] = useState("");
  const state = useAsync(() => api("/api/traffic"), [refreshKey]);
  const flows = state.data || [];

  useEffect(() => {
    if (!selected && flows.length) setSelected(flows[0].id);
  }, [flows, selected]);

  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setDetailError("");
    api(`/api/traffic/${encodeURIComponent(selected)}`)
      .then((flow) => !cancelled && setDetail(flow))
      .catch((err) => !cancelled && setDetailError(err.message));
    return () => { cancelled = true; };
  }, [selected, refreshKey]);

  if (state.loading || state.error) return <PageState state={state} />;
  return (
    <div className="workbench">
      <aside className="workbench-sidebar">
        <div className="workbench-head">
          <div>
            <h2>Traffic</h2>
            <p>Captured requests, responses, and replay sources.</p>
          </div>
          <div className="actions">
            <button className="secondary" onClick={async () => { await del("/api/traffic"); setSelected(""); refresh(); }}><Trash2 />Clear</button>
            <a className="secondary" href={`/api/traffic/export?token=${encodeURIComponent(getToken())}`}><FileJson />JSON</a>
            <a className="secondary" href={`/api/traffic/export?format=har&token=${encodeURIComponent(getToken())}`}><Download />HAR</a>
          </div>
        </div>
        <div className="workbench-list">
          {flows.length ? flows.map((flow) => (
            <FlowRow key={flow.id} flow={flow} active={flow.id === selected} onSelect={() => setSelected(flow.id)} />
          )) : <EmptyList>No traffic captured yet.</EmptyList>}
        </div>
      </aside>
      <section className="workbench-main">
        {detailError && <div className="detail-shell error">{detailError}</div>}
        {!detail && !detailError && <EmptyDetail title="Request Detail" body="Select a captured flow to inspect headers, parameters, and body samples." />}
        {detail && <TrafficDetail flow={detail} setCurrent={setCurrent} refresh={refresh} />}
      </section>
    </div>
  );
}

function FlowRow({ flow, active, onSelect }) {
  const method = flow.method || "REQ";
  return (
    <button className={`list-row ${active ? "active" : ""}`} onClick={onSelect}>
      <div className="list-row-title">
        <MethodPill method={method} />
        <span>{flow.host || "(unknown host)"}</span>
      </div>
      <div className="list-row-meta">{flow.status ? `status ${flow.status}` : "pending"} · {flow.duration_ms !== undefined ? `${flow.duration_ms} ms` : "duration unknown"} · {flow.created_at || ""}</div>
      <div className="list-row-meta">{flow.url || flow.id}</div>
    </button>
  );
}

function TrafficDetail({ flow, setCurrent, refresh }) {
  const reqHeaders = (flow.headers || []).filter((h) => h.direction === "request");
  const respHeaders = (flow.headers || []).filter((h) => h.direction === "response");
  return (
    <div className="detail-shell">
      <div className="detail-topbar">
        <div className="detail-title">
          <h2>Request Detail</h2>
          <div className="url-line">{flow.url || ""}</div>
        </div>
        <div className="detail-actions">
          <button className="secondary" onClick={async () => {
            const created = await postJSON("/api/repeater/cases", { source_flow_id: flow.id });
            sessionStorage.setItem("selectedRepeaterCase", created.id);
            setCurrent("Repeater");
          }}><Repeat />Clone</button>
          <button className="secondary" onClick={async () => { await post(`/api/traffic/${encodeURIComponent(flow.id)}/replay`); refresh(); }}><Play />Replay</button>
        </div>
      </div>
      <div className="grid metrics-grid compact">
        <Metric label="Method" value={flow.method || ""} />
        <Metric label="Status" value={flow.status || ""} />
        <Metric label="Duration" value={`${flow.duration_ms || 0} ms`} />
        <Metric label="Cache" value={flow.cache_hit ? "hit" : "miss"} />
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

function RepeaterView({ refreshKey, refresh }) {
  const [selected, setSelected] = useState(sessionStorage.getItem("selectedRepeaterCase") || "");
  const state = useAsync(() => api("/api/repeater/cases"), [refreshKey]);
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
              });
              setSelected(created.id);
              refresh();
            }}><Plus />New</button>
          </div>
        </div>
        <div className="workbench-list">
          {cases.length ? cases.map((c) => <RepeaterRow key={c.id} item={c} active={c.id === selected} onSelect={() => setSelected(c.id)} />) : <EmptyList>No saved cases yet.</EmptyList>}
        </div>
      </aside>
      <section className="workbench-main">
        {detailError && <div className="detail-shell error">{detailError.message}</div>}
        {!detail && !detailError && <EmptyDetail title="Request Builder" body="Create a case or clone a captured request from Traffic." />}
        {detail && <RepeaterEditor detail={detail} refresh={refresh} clearSelected={() => setSelected("")} />}
      </section>
    </div>
  );
}

function isNotFound(error) {
  return Boolean(error && /^404\b/.test(error.message || ""));
}

function RepeaterRow({ item, active, onSelect }) {
  return (
    <button className={`list-row ${active ? "active" : ""}`} onClick={onSelect}>
      <div className="list-row-title">
        <MethodPill method={item.method || "REQ"} />
        <span>{item.name || item.id}</span>
      </div>
      <div className="list-row-meta">{item.url || ""}</div>
      <div className="list-row-meta">{item.source_flow_id ? `source ${item.source_flow_id}` : "manual case"} - {item.updated_at || ""}</div>
    </button>
  );
}

function RepeaterEditor({ detail, refresh, clearSelected }) {
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
  const update = (key, value) => setForm((prev) => ({ ...prev, [key]: value }));
  const payload = () => ({
    name: form.name,
    method: form.method,
    url: form.url,
    timeout_ms: Number(form.timeout_ms),
    headers: form.headersText.trim() ? JSON.parse(form.headersText) : {},
    body: form.body,
  });
  const save = async () => {
    await putJSON(`/api/repeater/cases/${encodeURIComponent(c.id)}`, payload());
    refresh();
  };

  return (
    <div className="detail-shell">
      <div className="detail-topbar">
        <div className="detail-title">
          <h2>Request Builder</h2>
          <div className="url-line">{c.name || c.id}</div>
        </div>
        <div className="detail-actions">
          <button className="secondary" onClick={save}><Save />Save</button>
          <button className="primary" onClick={async () => { await save(); await post(`/api/repeater/cases/${encodeURIComponent(c.id)}/send`); refresh(); }}><Send />Send</button>
          <button className="secondary danger-button" onClick={async () => { await del(`/api/repeater/cases/${encodeURIComponent(c.id)}`); clearSelected(); refresh(); }}><Trash2 />Delete</button>
        </div>
      </div>
      <div className="editor-stack">
        <label>Name<input value={form.name} onChange={(e) => update("name", e.target.value)} /></label>
        <div className="request-line">
          <label>Method<input value={form.method} onChange={(e) => update("method", e.target.value)} /></label>
          <label>URL<input value={form.url} onChange={(e) => update("url", e.target.value)} /></label>
          <label>Timeout ms<input type="number" value={form.timeout_ms} onChange={(e) => update("timeout_ms", e.target.value)} /></label>
        </div>
        <div className="split-grid">
          <div className="section-card"><h3>Headers JSON</h3><textarea value={form.headersText} onChange={(e) => update("headersText", e.target.value)} /></div>
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

function CertificatesView({ refreshKey, refresh }) {
  const state = useAsync(async () => {
    const [ca, leaf] = await Promise.all([api("/api/certificates/ca"), api("/api/certificates/leaf")]);
    return { ca, leaf };
  }, [refreshKey]);
  const [paths, setPaths] = useState({ cert_path: "", key_path: "" });
  if (state.loading || state.error) return <PageState state={state} />;
  const { ca, leaf } = state.data;
  return (
    <div className="page-stack">
      <PageTitle title="Certificates" subtitle="CA trust material and generated leaf certificates." />
      <div className="grid metrics-grid"><Metric label="Subject" value={ca.subject} /><Metric label="Expires" value={ca.expires_at} /><Metric label="Path" value={ca.path} /></div>
      <div className="panel"><h2>Fingerprint</h2><code>{ca.fingerprint}</code><div className="actions"><a className="primary" href={`/api/certificates/ca/download?token=${encodeURIComponent(getToken())}`}><Download />Download CA</a><button className="secondary" onClick={async () => { await post("/api/certificates/ca/rotate"); refresh(); }}><RefreshCw />Rotate CA</button></div><div className="actions"><input placeholder="cert path" value={paths.cert_path} onChange={(e) => setPaths({ ...paths, cert_path: e.target.value })} /><input placeholder="key path" value={paths.key_path} onChange={(e) => setPaths({ ...paths, key_path: e.target.value })} /><button className="secondary" onClick={async () => { await postJSON("/api/certificates/ca/import", paths); refresh(); }}>Import CA</button></div></div>
      <div className="panel"><h2>Trust Instructions</h2><table><tbody><tr><td>Windows</td><td>Import into Trusted Root Certification Authorities.</td></tr><tr><td>macOS</td><td>Import into Keychain Access and set Always Trust.</td></tr><tr><td>Linux</td><td>Install into the system CA store or browser-specific store.</td></tr><tr><td>Firefox</td><td>Import under Privacy & Security, Certificates, Authorities.</td></tr></tbody></table></div>
      <div className="panel"><h2>Leaf Certificates</h2><table><thead><tr><th>Host</th><th>Subject</th><th>Expires</th><th>Fingerprint</th></tr></thead><tbody>{leaf.map((cert) => <tr key={cert.host}><td>{cert.host}</td><td>{cert.subject}</td><td>{cert.expires_at}</td><td><code>{cert.fingerprint}</code></td></tr>)}</tbody></table></div>
    </div>
  );
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
  if (state.loading || state.error) return <PageState state={state} />;
  const { deployment, logs } = state.data;
  return <div className="page-stack"><PageTitle title="Deployments" subtitle="Runtime controls, profiles, and recent log output." /><div className="grid metrics-grid"><Metric label="Status" value={deployment.status} /><Metric label="Listen address" value={deployment.listen_addr} /><Metric label="MITM" value={deployment.mitm_enabled ? "enabled" : "disabled"} /><Metric label="Config" value={deployment.config_path || "defaults"} /></div><div className="panel"><h2>Controls</h2><div className="actions"><button className="secondary" onClick={async () => { await post("/api/deployments/current/reload"); refresh(); }}><RefreshCw />Reload config</button><button className="secondary" onClick={async () => { await post("/api/deployments/current/restart"); refresh(); }}>Restart</button></div></div><TextCard title="Logs" value={(logs || []).join("\n")} /><div className="panel"><h2>Profiles</h2><table><thead><tr><th>Name</th><th>Kind</th><th>Description</th></tr></thead><tbody>{(deployment.profiles || []).map((p) => <tr key={p.name}><td>{p.name}</td><td>{p.kind}</td><td>{p.description}</td></tr>)}</tbody></table></div></div>;
}

function CacheView({ refreshKey, refresh }) {
  const state = useAsync(() => api("/api/cache"), [refreshKey]);
  const [domain, setDomain] = useState("");
  if (state.loading || state.error) return <PageState state={state} />;
  const cache = state.data;
  return <div className="page-stack"><PageTitle title="Cache" subtitle="HTTP response cache inventory and purge controls." /><div className="grid metrics-grid"><Metric label="Enabled" value={cache.enabled ? "yes" : "no"} /><Metric label="Directory" value={cache.directory} /><Metric label="TTL" value={`${cache.ttl}s`} /><Metric label="Entries" value={cache.entries} /><Metric label="Hit rate" value={`${cache.hits || 0}/${(cache.hits || 0) + (cache.misses || 0)}`} /><Metric label="Size" value={`${cache.size} bytes`} /></div><div className="panel"><h2>Purge</h2><div className="actions"><input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="optional domain" /><button className="secondary" onClick={async () => { await postJSON("/api/cache/purge", { domain }); refresh(); }}>Purge</button></div></div><div className="panel"><h2>Cached Entries</h2><table><thead><tr><th>URL</th><th>Status</th><th>Expires</th><th>Size</th></tr></thead><tbody>{(cache.items || []).map((i) => <tr key={i.url}><td>{i.url}</td><td>{i.status}</td><td>{i.expires_at}</td><td>{i.size || 0}</td></tr>)}</tbody></table></div></div>;
}

function SettingsView({ refreshKey, refresh }) {
  const state = useAsync(() => api("/api/settings"), [refreshKey]);
  const [form, setForm] = useState(null);
  useEffect(() => { if (state.data) setForm(state.data); }, [state.data]);
  if (state.loading || state.error || !form) return <PageState state={state} />;
  const capture = form.traffic_capture || {};
  const set = (patch) => setForm((prev) => ({ ...prev, ...patch }));
  return <div className="page-stack"><PageTitle title="Settings" subtitle="Runtime behavior and capture policy." /><div className="panel"><div className="detail-topbar"><h2>Settings</h2><button className="primary" onClick={async () => { await putJSON("/api/settings", form); refresh(); }}><Save />Save</button></div><div className="settings-grid"><label><input type="checkbox" checked={!!form.enable_mitm} onChange={(e) => set({ enable_mitm: e.target.checked })} /> Enable MITM</label><label><input type="checkbox" checked={!!form.verbose_logging} onChange={(e) => set({ verbose_logging: e.target.checked })} /> Verbose logging</label><label><input type="checkbox" checked={!!form.log_requests} onChange={(e) => set({ log_requests: e.target.checked })} /> Request logging</label><label>TLS minimum<input value={form.min_tls_version || ""} onChange={(e) => set({ min_tls_version: e.target.value })} /></label><label>Idle timeout<input type="number" value={form.idle_timeout_seconds || 0} onChange={(e) => set({ idle_timeout_seconds: Number(e.target.value) })} /></label></div><h3>Traffic Capture</h3><div className="settings-grid"><label><input type="checkbox" checked={!!capture.store_bodies} onChange={(e) => set({ traffic_capture: { ...capture, store_bodies: e.target.checked } })} /> Store body samples</label><label><input type="checkbox" checked={capture.redact_bodies !== false} onChange={(e) => set({ traffic_capture: { ...capture, redact_bodies: e.target.checked } })} /> Redact body samples</label><label>Max body bytes<input type="number" value={capture.max_body_bytes || 32768} onChange={(e) => set({ traffic_capture: { ...capture, max_body_bytes: Number(e.target.value) } })} /></label></div><h3>Excluded Domains</h3><textarea value={(form.excluded_domains || []).join("\n")} onChange={(e) => set({ excluded_domains: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean) })} /><CodeCard title="Cache" value={form.cache || {}} /></div></div>;
}

function AdminUsersView({ refreshKey, refresh }) {
  const state = useAsync(() => api("/api/admin/users"), [refreshKey]);
  const [form, setForm] = useState({ name: "", role: "read" });
  if (state.loading || state.error) return <PageState state={state} />;
  return <div className="page-stack"><PageTitle title="Admin Users" subtitle="Named dashboard users for audit and operational roles." /><div className="panel"><div className="actions"><input placeholder="name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /><select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}><option value="read">Read only</option><option value="admin">Admin</option></select><button className="secondary" onClick={async () => { await postJSON("/api/admin/users", form); setForm({ name: "", role: "read" }); refresh(); }}><Plus />Add</button></div><table><thead><tr><th>Name</th><th>Role</th><th>Created</th><th /></tr></thead><tbody>{state.data.map((u) => <tr key={u.id}><td>{u.name}</td><td><span className={`badge ${u.role === "admin" ? "warn" : "allow"}`}>{u.role}</span></td><td>{u.created_at}</td><td><button className="rowbutton" onClick={async () => { await del(`/api/admin/users/${u.id}`); refresh(); }}>Delete</button></td></tr>)}</tbody></table><p className="muted">Bearer tokens still enforce API access; this list records named dashboard users and roles.</p></div></div>;
}

function AuditLogView({ refreshKey }) {
  const state = useAsync(() => api("/api/audit"), [refreshKey]);
  if (state.loading || state.error) return <PageState state={state} />;
  return <div className="page-stack"><PageTitle title="Audit Log" subtitle="Administrative activity and system events." /><div className="panel"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>{state.data.map((e) => <tr key={`${e.created_at}-${e.action}`}><td>{e.created_at}</td><td>{e.actor}</td><td>{e.action}</td><td><code>{e.details ? JSON.stringify(e.details) : ""}</code></td></tr>)}</tbody></table></div></div>;
}

function ThreatScannerView({ refreshKey, refresh }) {
  const state = useAsync(() => api("/api/threats/events"), [refreshKey]);
  const [detail, setDetail] = useState(null);
  if (state.loading || state.error) return <PageState state={state} />;
  const data = state.data;
  const m = data.metrics;
  return <div className="page-stack"><PageTitle title="Threat Scanner" subtitle="Detection stream, verdicts, and rule activity." /><div className="grid metrics-grid"><Metric label="Scanned requests" value={m.scanned_requests} /><Metric label="Scanned responses" value={m.scanned_responses} /><Metric label="Warnings" value={m.warnings} /><Metric label="Blocked threats" value={m.blocked_threats} /><Metric label="Quarantine" value={m.quarantined} /><Metric label="AI calls" value={m.ai_calls} /><Metric label="Average latency" value={`${Number(m.average_scan_latency_ms).toFixed(1)} ms`} /><Metric label="Timeouts" value={m.timeouts} /></div><div className="panel"><h2>Live Detections</h2><table><thead><tr><th>Time</th><th>Target</th><th>Host</th><th>Action</th><th>Score</th><th>AI</th><th>Reason</th></tr></thead><tbody>{(data.events || []).map((e) => <tr key={e.id}><td>{e.timestamp}</td><td>{e.target}</td><td>{e.host || ""}</td><td><span className={`badge ${e.verdict.action}`}>{e.verdict.action}</span></td><td>{e.local_result ? e.local_result.score : ""}</td><td>{e.ai_used ? "yes" : "no"}</td><td><button className="rowbutton" onClick={async () => setDetail(await api(`/api/threats/events/${e.id}`))}>{e.verdict.reason}</button></td></tr>)}</tbody></table></div><div className="panel"><h2>Top Rules</h2><table><thead><tr><th>ID</th><th>Name</th><th>Hits</th><th>False positives</th></tr></thead><tbody>{(m.top_rules || []).map((r) => <tr key={r.id}><td><code>{r.id}</code></td><td>{r.name}</td><td>{r.hits}</td><td>{r.false_positive_overrides}</td></tr>)}</tbody></table></div>{detail ? <ThreatDetail event={detail} refresh={refresh} /> : <div className="panel"><h2>Detection Detail</h2><p>Select a detection reason to inspect signals, AI output, and redaction details.</p></div>}</div>;
}

function ThreatDetail({ event, refresh }) {
  const signals = ((event.local_result && event.local_result.signals) || []);
  const override = async (action) => { await post(`/api/threats/events/${event.id}/${action}`); refresh(); };
  return <div className="panel"><div className="detail-topbar"><h2>Detection Detail</h2><div className="actions"><button className="secondary" onClick={() => override("false-positive")}>Mark false positive</button><button className="secondary" onClick={() => override("allow")}>Allow</button><button className="secondary" onClick={() => override("block")}>Block</button><button className="secondary" onClick={() => override("quarantine")}>Quarantine</button></div></div><div className="grid metrics-grid compact"><Metric label="Final action" value={event.verdict.action} /><Metric label="Local score" value={event.local_result.score} /><Metric label="AI used" value={event.ai_used ? "yes" : "no"} /><Metric label="Latency" value={`${event.scan_latency_ms} ms`} /></div><h3>Signals</h3><table><thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Severity</th><th>Weight</th><th>Evidence</th></tr></thead><tbody>{signals.map((s) => <tr key={s.id}><td><code>{s.id}</code></td><td>{s.name}</td><td>{s.category}</td><td>{s.severity}</td><td>{s.weight}</td><td><code>{JSON.stringify(s.evidence || {})}</code></td></tr>)}</tbody></table><CodeCard title="AI Verdict" value={event.ai_verdict || {}} /><CodeCard title="Redaction" value={(event.evidence && event.evidence.redaction) || {}} /><CodeCard title="Quarantine" value={(event.evidence && event.evidence.quarantine) || {}} /></div>;
}

function PageTitle({ title, subtitle }) {
  return <div className="page-title"><div><h1>{title}</h1><p>{subtitle}</p></div></div>;
}

function Metric({ label, value }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong></div>;
}

function MethodPill({ method }) {
  const upper = String(method || "").toUpperCase();
  return <span className={`method-pill ${METHOD_CLASS[upper] || ""}`}>{upper}</span>;
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

function TextCard({ title, value }) {
  return <div className="section-card"><h3>{title}</h3><pre>{value}</pre></div>;
}

createRoot(document.getElementById("root")).render(<App />);
