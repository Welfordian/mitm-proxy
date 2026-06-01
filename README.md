 # Go MITM Proxy

<p align="center">
  <img src="docs/assets/logo-mark.svg" alt="MITM Proxy Admin logo mark" width="64" height="64">
</p>

 A lightweight, developer-friendly Man‑in‑the‑Middle (MITM) HTTP/HTTPS proxy written in Go. It supports HTTP/1.1 and HTTP/2, CONNECT tunneling, WebSocket tunneling (ws/wss), on‑disk response caching with flexible filters, and live config reloading.

 ## Badges

 ![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)
 ![Platform](https://img.shields.io/badge/Platforms-linux%20|%20macOS%20|%20windows-informational)
 ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

## Admin Dashboard Preview

![MITM Proxy Admin dashboard overview](docs/assets/admin-dashboard.png)

![MITM Proxy Admin traffic workbench](docs/assets/admin-traffic.png)

![MITM Proxy Admin repeater workbench](docs/assets/admin-repeater-empty.png)



 ## Overview

 Go MITM Proxy is an intercepting proxy intended for debugging, testing, learning, and controlled interception of HTTP(S) traffic. When MITM is enabled, it dynamically generates per‑host leaf certificates signed by a local CA, allowing the proxy to decrypt and inspect HTTPS traffic. It can also work as a transparent TCP tunnel when MITM is disabled or for excluded domains/ports.

## Notice and Responsible-Use Requirements

**Important:** This application performs active **Man-in-the-Middle (MITM) interception**, including the generation and use of TLS certificates to decrypt HTTPS traffic. Depending on your jurisdiction and network environment, **intercepting traffic without clear, prior consent from all affected users may be illegal** and can violate privacy, workplace policy, or regulatory requirements.

Before using this software in any environment other than your own local machine:

### 1. Obtain Explicit Consent
All users of any network where this proxy may intercept traffic must be clearly informed that HTTP(S) interception and inspection will occur. Consent should be explicit and ideally documented.

### 2. Use Only on Authorized Networks
Do not run this software on networks you do not own, administer, or have explicit authorization to test or monitor.

### 3. Respect Privacy and Data Protection Laws
Many regions have strict laws governing the interception, logging, and storage of user data (e.g., GDPR, CCPA, wiretap laws). **You are responsible** for ensuring your use complies with all applicable regulations.

### 4. Secure the Generated CA Key
The generated CA private key (usually `ca-key.pem`) allows the holder to impersonate *any* domain for users who trust the corresponding certificate.

- Store it securely.
- Never share it.
- Rotate/delete it if compromised.

### 5. Use for Testing and Debugging Only
This proxy is designed for development, debugging, controlled testing, or educational purposes — **not** for covert monitoring or unauthorized surveillance.

---

By using this software, **you acknowledge and accept full responsibility** for ensuring your usage is lawful, ethical, and properly communicated to all affected users.


 ## Features

 - HTTP and HTTPS proxying via standard proxy semantics
 - MITM interception for HTTPS with per‑host certificates
 - HTTP/1.1 and HTTP/2 downstream handling with ALPN negotiation
 - WebSocket tunneling: ws:// and wss://
 - Flexible on‑disk cache for GET responses
   - Include/exclude by domain and by file extension
   - TTL‑based expiration
   - Cache hit indicators in responses (Via and a custom x-<normalized-proxy-name>-uid header)
- Live config reload: optional polling of config.json and hot‑apply of changes
- Local admin API/dashboard with bearer-token auth, read-only token support, admin user role records, health/version/audit endpoints, live traffic SSE, and CA metadata/download
- Runtime blocking policy for ports, domains, and IP/CIDR ranges
- Optional threat scanner with heuristic and AI-backed verdicts, redaction, verdict caching, quarantine metadata, and dashboard endpoints
- Verbose and per‑request logging controls
- Sensible defaults with optional JSON configuration

 ## Installation

 Prerequisites:
 - Go 1.25 or newer

 Clone and build:

 ```bash
 git clone https://github.com/Welfordian/mitm-proxy.git
 cd mitm-proxy
 go build ./
 ```

 This produces a mitm-proxy (or mitm-proxy.exe on Windows) binary in the project root.


 ## Quick Start

 1) Run the proxy with defaults (listens on :8080):

 ```bash
 ./mitm-proxy
 ```

 On first start, a local CA will be created and saved to ca-cert.pem and ca-key.pem.

 2) Configure your browser or curl to use the proxy at http://localhost:8080.

 3) Trust the generated CA certificate (ca-cert.pem) in your OS/browser to allow HTTPS interception. See Trusting the Local CA.

 4) Visit an HTTPS site through the proxy and observe logs. Use verbose mode for more detail:

 ```bash
 ./mitm-proxy --verbose
 ```


 ## Usage

 ### Command-line Flags

 - --config string: Path to config.json file
 - --listen string: Listen address (overrides config)
 - --ca-cert string: Path to existing CA certificate (overrides config)
 - --ca-key string: Path to existing CA key (overrides config)
 - --mitm bool: Enable MITM interception (default true; setting to false forces tunneling)
- --verbose bool: Enable verbose logging
- --watch-config bool: Watch the config.json for changes and auto‑apply (default true)
- --admin-enabled bool: Enable local admin API/dashboard (default true)
- --admin-addr string: Admin API/dashboard listen address (default 127.0.0.1:9090)
- --admin-token string: Admin bearer token (generated at startup if omitted)
- --admin-read-token string: Read-only bearer token for GET/HEAD/OPTIONS admin access
- --admin-ui bool: Serve embedded admin UI (default true)
- --admin-store string: Admin SQLite store path (default dashboard.db)

 CLI flags override configuration file values where noted.


 ### Configuration (config.json)

 An example config.json is included in the repo:

 ```json
 {
  "listen_addr": ":8080",
  "proxy_name": "MITM-Proxy",
  "ca_cert_path": null,
  "ca_key_path": null,
  "ca_cert_output_path": "ca-cert.pem",
  "ca_key_output_path": "ca-key.pem",
  "enable_mitm": true,
  "admin_enabled": true,
  "admin_addr": "127.0.0.1:9090",
  "admin_token": "",
  "admin_read_token": "",
  "admin_ui": true,
  "admin_store": "dashboard.db",
  "excluded_domains": [],
  "blocked_ports": [25, 445, 3389],
  "blocked_domains": [],
  "blocked_ips": [],
  "block_action": "deny",
  "block_response_status": 403,
  "traffic_capture": {
    "store_bodies": false,
    "max_body_bytes": 32768,
    "redact_bodies": true
  },
  "verbose_logging": true,
  "log_requests": true,
  "max_idle_conns": 200,
  "idle_conn_timeout_seconds": 90,
  "tls_handshake_timeout_seconds": 10,
  "min_tls_version": "1.2",
  "tls_next_protos": ["h2", "http/1.1"],
  "cache": {
    "enabled": true,
    "directory": "/var/cache/mitm-proxy",
    "include_domains": [],
    "exclude_domains": [],
    "include_extensions": ["jpg", "png", "webp", "css", "js"],
    "exclude_extensions": [],
    "ttl": 3600
  }
}
 ```

 Notes:
- If ca_cert_path/ca_key_path are not provided, the proxy writes a generated CA to ca-cert.pem / ca-key.pem.
- excluded_domains supports wildcards (see IsDomainExcluded in internal/config).
- admin_addr defaults to localhost. If admin_token is empty, a per-run token is generated and printed at startup.
- admin_read_token can be set for read-only dashboard/API clients.
- traffic_capture.store_bodies is disabled by default; when enabled, body samples are size-limited and redacted by default.
- blocked_domains supports exact names and wildcard patterns such as *.example.com; blocked_ips supports single IPs and CIDR ranges.
- cache.include_domains and cache.exclude_domains are mutually exclusive, same for include_extensions vs exclude_extensions.
- The watcher only monitors the file given to --config or the default ./config.json, and applies changes hot via Proxy.SetConfig.

### Admin Dashboard

The admin server serves the dashboard at http://127.0.0.1:9090/admin/ by default. API routes require `Authorization: Bearer <token>`; for local browser use, `/admin/?token=<token>` stores the token in browser local storage.

Initial dashboard/API coverage includes:

- GET /api/health and GET /api/version
- GET /api/audit
- GET /api/traffic, GET /api/traffic/{id}, GET /api/traffic/stream, DELETE /api/traffic, and POST /api/traffic/{id}/replay
- GET /api/traffic/export?format=har for HAR-style export
- GET/POST/PUT/DELETE /api/repeater/cases and POST /api/repeater/cases/{id}/send for saved editable replay cases
- GET /api/certificates/ca, GET /api/certificates/ca/download, POST /api/certificates/ca/rotate, POST /api/certificates/ca/import, and GET /api/certificates/leaf
- GET/POST/DELETE block rules for ports, domains, and IPs
- GET /api/deployments/current, POST /api/deployments/current/reload, GET /api/logs, GET /api/cache with cached entries and hit/miss counts, POST /api/cache/purge, and GET/PUT /api/settings
- GET/POST/DELETE /api/admin/users for named admin/read-only user role records
- GET /api/threats/events, GET /api/threats/stream, GET /api/threats/config, POST /api/threats/test, and threat override endpoints
- GET /metrics for Prometheus-compatible process/admin/threat counters

The dashboard includes a first-run responsible-use confirmation. The CA private key is never exposed through the admin API.
Dashboard state is stored in SQLite at `dashboard.db` by default. Settings changed through the dashboard are applied immediately and written back to the configured JSON file, or to `config.json` when the proxy was started from defaults.

The admin frontend is a Vite/React app in `internal/admin/ui`. Its production build is emitted to `internal/admin/ui/dist` and embedded into the Go binary. To update the dashboard assets:

```bash
cd internal/admin/ui
npm install
npm run build
```

### Research Repeater

The dashboard's **Repeater** view lets security researchers clone captured HTTP traffic into saved editable cases. A case stores the method, URL, headers, body sample, timeout, and optional source traffic flow ID. Each send stores a run with status, duration, response headers, a capped response body sample, and any upstream error.

Captured request bodies are only prefilled when `traffic_capture.store_bodies` was enabled at capture time. If body redaction was enabled, the repeater receives the redacted sample; uncaptured bodies remain empty and can be edited manually.

The legacy `POST /api/traffic/{id}/replay` endpoint remains available for one-shot replay, while the repeater is intended for repeatable request mutation and response comparison.

### AI Threat Scanning

The threat scanner can inspect HTTP requests and responses with local heuristics and, when configured, ask OpenAI for a second opinion before blocking suspicious traffic.

1. Create an OpenAI API key and expose it to the proxy process:

```powershell
$env:OPENAI_API_KEY = "sk-..."
```

On macOS/Linux:

```bash
export OPENAI_API_KEY="sk-..."
```

2. Enable the scanner in `config.json`:

```json
{
  "threat_scanner": {
    "enabled": true,
    "mode": "suspicious_only",
    "provider": "openai",
    "model": "gpt-5.4-nano",
    "second_opinion_model": "gpt-5.4-mini",
    "scan_requests": true,
    "scan_responses": true,
    "max_body_bytes": 131072,
    "max_ai_body_bytes": 32768,
    "ai_timeout_ms": 750,
    "block_threshold": 0.85,
    "warn_threshold": 0.65,
    "require_ai_confirmation_for_block": true,
    "block_critical_local_on_ai_failure": true,
    "fail_open": true,
    "scan_content_types": [
      "text/html",
      "text/plain",
      "application/json",
      "application/javascript",
      "text/javascript",
      "application/xml"
    ],
    "skip_content_types": [
      "image/",
      "video/",
      "audio/",
      "font/",
      "application/octet-stream"
    ],
    "trusted_domains": [
      "accounts.google.com",
      "login.microsoftonline.com",
      "github.com"
    ],
    "allowlist_domains": [],
    "malicious_domains": [],
    "malicious_file_hashes": [],
    "threat_intel_updated": "",
    "quarantine_dir": "quarantine",
    "debug_log_path": "threats.log",
    "redact_before_ai": true,
    "store_bodies": false,
    "openai_api_key_env": "OPENAI_API_KEY"
  }
}
```

3. Start the proxy:

```bash
go run . --config ./config.json
```

The dashboard's **Threat Scanner** view shows scanned request/response counts, AI call counts, detections, verdict details, top local rules, and override actions.

Scanner modes:

- `suspicious_only`: default; local heuristics decide when to call AI.
- `all_text`: calls AI for text-like traffic.
- `paranoid`: also calls AI for text-like traffic and is intended for high-sensitivity testing.
- `metadata_only`: uses headers, URL, host, and metadata without AI body review.
- `off`: disables scanning.

Useful safety and privacy controls:

- `redact_before_ai`: redacts common secrets and personal data before sending evidence to OpenAI.
- `max_ai_body_bytes`: limits the body sample included in AI evidence.
- `require_ai_confirmation_for_block`: prevents local heuristics from blocking unless AI confirms, except where `block_critical_local_on_ai_failure` is enabled for critical local evidence.
- `fail_open`: allows traffic when the scanner fails, unless stricter blocking settings apply.
- `trusted_domains` and `allowlist_domains`: reduce false positives for known-good hosts.
- `malicious_domains` and `malicious_file_hashes`: add local threat-intel hits without waiting for AI.
- `debug_log_path`: writes scanner decisions to a local JSONL-style log for debugging.

To use a different environment variable name for the API key, set `openai_api_key_env` and export that variable before starting the proxy. Do not put API keys directly in `config.json`.


 ### Trusting the Local CA

 To intercept HTTPS, import and trust ca-cert.pem in your OS/browser:
 - macOS: Keychain Access → login/system → Certificates → import ca-cert.pem → set Always Trust.
 - Windows: certmgr.msc → Trusted Root Certification Authorities → Certificates → import ca-cert.pem.
 - Linux (varies): e.g., update-ca-certificates, or browser‑specific store (Firefox: Settings → Privacy & Security → Certificates → View → Authorities → Import).

 Without trusting the CA, browsers will show certificate warnings for intercepted sites.


 ### Using the Proxy

 Set your HTTP/HTTPS proxy to the listen address (default http://localhost:8080).

 Examples with curl:

 ```bash
 # HTTP
 curl -x http://localhost:8080 http://example.com/

 # HTTPS (after trusting the CA for full MITM)
 curl -x http://localhost:8080 https://example.com/

 # Disable MITM and tunnel only
 ./mitm-proxy --mitm=false

 # Change listen address
 ./mitm-proxy --listen=127.0.0.1:9090
 ```

 WebSocket notes:
 - ws:// is handled by HTTP handler via connection hijacking.
 - wss:// is detected on the HTTP/1.1 MITM path and tunneled end‑to‑end after the initial handshake.


 ## Caching

 The cache is file‑based and only considers HTTP GET requests when enabled. Selection is controlled by:
 - cache.include_domains / cache.exclude_domains (host matching)
 - cache.include_extensions / cache.exclude_extensions (URL path extension, case‑insensitive)
 - cache.ttl (seconds)

 On a cache hit, responses include:
 - Via: <proxy_name>
 - x-<normalized-proxy-name>-uid: a stable identifier derived from the cache file hash

 Cache directory is ensured on startup and on config changes. If no directory is set, it defaults to ./cache.


 ## Build and Run

 ```bash
 go build ./
 ./mitm-proxy --config ./config.json
 ```

 The server binds to the configured listen_addr and handles HTTP + HTTPS with ALPN.

 ## Roadmap

 - Proxy authentication (Basic/NTLM) and ACLs
 - Upstream proxy/chaining support
 - PAC file generation and helper scripts
 - UI for inspecting flows and cache entries
 - TLS fingerprinting controls and JA3 styling
 - Metrics/health endpoints and Prometheus integration


 ## Contributing

 Issues and pull requests are welcome. For significant changes, please open an issue first to discuss scope and design.

 Coding style: keep changes minimal and focused; prefer clarity and small, composable functions.
