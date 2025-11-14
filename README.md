 # Go MITM Proxy

 A lightweight, developer-friendly Man‑in‑the‑Middle (MITM) HTTP/HTTPS proxy written in Go. It supports HTTP/1.1 and HTTP/2, CONNECT tunneling, WebSocket tunneling (ws/wss), on‑disk response caching with flexible filters, and live config reloading.

 ## Badges

 ![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)
 ![Platform](https://img.shields.io/badge/Platforms-linux%20|%20macOS%20|%20windows-informational)
 ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)


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
  "excluded_domains": [],
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
 - cache.include_domains and cache.exclude_domains are mutually exclusive, same for include_extensions vs exclude_extensions.
 - The watcher only monitors the file given to --config or the default ./config.json, and applies changes hot via Proxy.SetConfig.


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


 ## License

 No LICENSE file is present in the repository at the time of writing. By default, this means all rights are reserved. If you intend others to use/fork this project, consider adding a standard open‑source license (e.g., MIT, Apache‑2.0, BSD‑3‑Clause) and update this section and badge accordingly.