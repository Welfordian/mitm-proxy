# Deployment Profiles

The proxy can run as a local binary, a controlled LAN test instance, a Docker
container, or a systemd service. In every profile, keep the admin dashboard on
localhost unless a strong `--admin-token` is configured.

## Local

```bash
go build ./
./mitm-proxy --config ./config.json
```

Use the generated admin token printed at startup to open:

```text
http://127.0.0.1:9090/admin/?token=<token>
```

## LAN Test

Bind the proxy listener to the lab interface, keep the admin server protected,
and make sure every client is explicitly authorized for interception.

```bash
./mitm-proxy --listen 0.0.0.0:8080 --admin-addr 127.0.0.1:9090 --admin-token <secret>
```

## Docker

Mount persistent config, cache, dashboard database, and CA files. Do not bake
`ca-key.pem` into an image.

```bash
docker run --rm \
  -p 8080:8080 \
  -p 127.0.0.1:9090:9090 \
  -v "$PWD/config.json:/app/config.json:ro" \
  -v "$PWD/data:/app/data" \
  mitm-proxy:latest --config /app/config.json
```

## systemd

Use a dedicated user and keep generated CA material readable only by that user.

```ini
[Unit]
Description=MITM Proxy
After=network-online.target

[Service]
User=mitm-proxy
WorkingDirectory=/var/lib/mitm-proxy
ExecStart=/usr/local/bin/mitm-proxy --config /etc/mitm-proxy/config.json
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Restart support in the admin API intentionally returns `501 Not Implemented`
unless a supervisor-specific integration is added.
