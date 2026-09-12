# Deploying nginx reverse proxy with gdoc2netcfg

This documents how to deploy the gdoc2netcfg-generated nginx reverse proxy
configuration on a new site. The reference deployment is monarto
(`ten64.monarto.mithis.com`), deployed 2026-02-11.

## Prerequisites

### Debian packages from apt

```bash
sudo apt-get install -y \
    nginx \
    libnginx-mod-http-lua \
    libnginx-mod-http-ndk \
    libnginx-mod-stream \
    lua-resty-core \
    lua-resty-lrucache
```

### Debian packages from mithro's GitHub repos

Two packages are not in Debian's repositories and must be built from source
or downloaded from CI artifacts:

| Package                          | Repo                                                                                                   | Purpose                                              |
|----------------------------------|--------------------------------------------------------------------------------------------------------|------------------------------------------------------|
| `libnginx-mod-http-lua-upstream` | [mithro/libnginx-mod-http-lua-upstream](https://github.com/mithro/libnginx-mod-http-lua-upstream)      | `ngx.upstream` API (required by healthcheck library) |
| `libnginx-mod-stream-lua`        | [mithro/libnginx-mod-stream-lua-upstream](https://github.com/mithro/libnginx-mod-stream-lua-upstream)  | Lua scripting in the stream (TCP/UDP) module         |

Both repos have GitHub Actions workflows that build `.deb` packages for
debian-sid arm64 and amd64. Download the artifacts from the latest successful
run:

```bash
# From a machine with gh CLI authenticated:
gh run download <run-id> \
    --repo mithro/libnginx-mod-http-lua-upstream \
    --name debian-package-debian-sid-arm64 \
    --dir /tmp/debs/

gh run download <run-id> \
    --repo mithro/libnginx-mod-stream-lua-upstream \
    --name debian-package-debian-sid-arm64 \
    --dir /tmp/debs/

# Copy to target host and install:
scp /tmp/debs/*.deb user@target:/tmp/
ssh user@target "sudo dpkg -i /tmp/*.deb"
```

### lua-resty-upstream-healthcheck

This pure-Lua library is not yet packaged. Install it manually from
the upstream repo:

```bash
sudo mkdir -p /usr/share/lua/5.1/resty/upstream
sudo wget -q -O /usr/share/lua/5.1/resty/upstream/healthcheck.lua \
    https://raw.githubusercontent.com/openresty/lua-resty-upstream-healthcheck/master/lib/resty/upstream/healthcheck.lua
```

See [lua-resty-upstream-healthcheck-packaging.md](lua-resty-upstream-healthcheck-packaging.md)
for packaging details.

### Verification

After installing all packages, verify nginx loads cleanly:

```bash
sudo nginx -t
```

The modules-enabled directory should contain (in load order):

```
10-mod-http-ndk.conf         # NDK must load before Lua
50-mod-http-lua.conf         # HTTP Lua module
50-mod-stream.conf           # Stream module
60-mod-http-lua-upstream.conf  # Lua upstream API (after Lua)
70-mod-stream-lua.conf       # Stream Lua (after both stream and Lua)
```

## Configuration

### Enable the nginx generator

In `gdoc2netcfg.toml`, add `"nginx"` to the enabled generators list:

```toml
[generators]
enabled = ["dnsmasq_leaf", "nginx"]
```

The `[generators.nginx]` section should already exist with defaults:

```toml
[generators.nginx]
acme_webroot = "/var/www/acme"
# Optional settings (defaults shown):
# gdoc2netcfg_dir = "/etc/nginx/gdoc2netcfg"
# sites_enabled_dir = "/etc/nginx/sites-enabled"
# lua_healthcheck_path = "/usr/share/lua/5.1/"
```

### Generate configs

```bash
cd /opt/gdoc2netcfg
sudo uv run gdoc2netcfg fetch
sudo uv run gdoc2netcfg generate nginx
```

This produces a `nginx/` directory in the working directory containing:

```
nginx/
├── conf.d/
│   ├── healthcheck-setup.conf      # HTTP Lua healthcheck init_worker
│   └── healthcheck-status.conf     # localhost:8080 status endpoint
├── stream.d/
│   └── healthcheck-setup.conf      # Stream Lua healthcheck init_worker
├── scripts/
│   └── checker.lua                 # Custom HTTPS TCP health checker
└── sites-available/
    ├── host1.example.com/
    │   ├── http-proxy.conf         # HTTP server blocks
    │   ├── https-upstream.conf     # Stream upstreams
    │   └── https-map.conf          # SNI map entries
    └── host2.example.com/          # Multi-interface host
        ├── http-proxy.conf         # Combined + per-interface HTTP
        ├── https-upstream.conf     # Combined + per-interface upstreams
        ├── https-map.conf          # Root + per-interface SNI routes
        ├── http-healthcheck.lua    # HTTP health checker init
        ├── https-healthcheck.lua   # HTTPS health checker init
        └── https-balancer.lua      # Lua-based peer selection
```

### Deploy to /etc/nginx

```bash
sudo cp -a /opt/gdoc2netcfg/nginx/ /etc/nginx/gdoc2netcfg/
```

### nginx.conf

Replace the default `nginx.conf` to include gdoc2netcfg configs and add
the stream block:

```nginx
user www-data;
worker_processes auto;
worker_cpu_affinity auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens off;
    server_names_hash_bucket_size 128;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    access_log /var/log/nginx/access.log;

    gzip on;

    # gdoc2netcfg healthcheck infrastructure (Lua shared dicts, init_worker)
    include /etc/nginx/gdoc2netcfg/conf.d/*.conf;
    # Per-host HTTP configs from enabled site directories
    include /etc/nginx/sites-enabled/*/http-*.conf;
    # Standalone config files (default server, local server, etc.)
    include /etc/nginx/sites-enabled/*.conf;
}

stream {
    # gdoc2netcfg stream healthcheck infrastructure
    include /etc/nginx/gdoc2netcfg/stream.d/*.conf;
    # SNI-based TLS routing (includes per-host upstreams and map)
    include /etc/nginx/sites-enabled/00-https;
}
```

Key differences from the Debian default:
- `include /etc/nginx/gdoc2netcfg/conf.d/*.conf` for Lua healthcheck init
- `include /etc/nginx/sites-enabled/*/http-*.conf` for per-host-directory sites
- `stream` block for SNI-based HTTPS passthrough

### Hand-crafted config files

Three files must be created manually in `/etc/nginx/sites-available/`:

#### `00-https` — SNI stream router

This is the central piece that makes HTTPS passthrough work. It includes
per-host stream upstreams and SNI map entries from each enabled site
directory, then routes based on the TLS ClientHello SNI field.

```nginx
# SNI-based TLS routing
#
# Inspects TLS ClientHello SNI without terminating SSL.
# Per-host stream upstreams and map entries are generated by gdoc2netcfg
# and activated by symlinking per-host directories into sites-enabled/.

# Per-host stream upstreams (from enabled site directories)
include /etc/nginx/sites-enabled/*/https-upstream.conf;

map_hash_bucket_size 128;
map_hash_max_size 2048;

map $ssl_preread_server_name $tls_upstream {
    # Per-host SNI map entries (from enabled site directories)
    include /etc/nginx/sites-enabled/*/https-map.conf;

    default                     local_https;
}

upstream local_https {
    server 127.0.0.1:8443;
}

server {
    listen 443;
    listen [::]:443;

    ssl_preread on;
    proxy_pass $tls_upstream;
}
```

Unknown SNI names (or no SNI) fall through to `local_https` →
`127.0.0.1:8443`, where the default HTTP server block handles them.

#### `00-http-default.conf` — catch-all server

Returns 444 (close connection) for unrecognised hostnames on both HTTP
and the local HTTPS port:

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 127.0.0.1:8443 ssl default_server;
    listen [::1]:8443 ssl default_server;

    server_name _;

    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    return 444;
}
```

The snakeoil cert is needed because `ssl` on the listen directive requires
a certificate, even though we immediately close the connection.

#### `ten64.<site>.mithis.com-http-local.conf` — status endpoints

The gateway host itself is not an HTTP backend, so it needs a manual config
for local content and healthcheck status pages:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name ten64.<site>.mithis.com ten64 <site>.mithis.com;

    root /var/www/html;
    index index.html;

    location /.well-known/acme-challenge/ {
        root /var/www/acme;
    }

    location /status-http {
        default_type text/plain;
        content_by_lua_block {
            local hc = require "resty.upstream.healthcheck"
            ngx.say(hc.status_page())
        }
    }

    location /status-https {
        default_type text/plain;
        alias /etc/nginx/gdoc2netcfg/status.txt;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}

server {
    listen 127.0.0.1:8443 ssl;
    server_name ten64.<site>.mithis.com ten64 <site>.mithis.com;

    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    root /var/www/html;
    index index.html;

    location /status-http {
        default_type text/plain;
        content_by_lua_block {
            local hc = require "resty.upstream.healthcheck"
            ngx.say(hc.status_page())
        }
    }

    location /status-https {
        default_type text/plain;
        alias /etc/nginx/gdoc2netcfg/status.txt;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}
```

Replace `<site>` with `welland` or `monarto`. The HTTPS server block
listens on `127.0.0.1:8443` (the local HTTPS port that the stream SNI
router forwards to for matching hostnames).

### Symlinks and directories

```bash
# Create ACME webroot for Let's Encrypt challenge responses
sudo mkdir -p /var/www/acme/.well-known/acme-challenge
sudo chown -R www-data:www-data /var/www/acme

# Create status file (must be writable by www-data)
sudo touch /etc/nginx/gdoc2netcfg/status.txt
sudo chown www-data:www-data /etc/nginx/gdoc2netcfg/status.txt

# Enable infrastructure configs
sudo ln -s /etc/nginx/sites-available/00-http-default.conf \
           /etc/nginx/sites-enabled/00-http-default.conf
sudo ln -s /etc/nginx/sites-available/00-https \
           /etc/nginx/sites-enabled/00-https
sudo ln -s /etc/nginx/sites-available/ten64.<site>.mithis.com-http-local.conf \
           /etc/nginx/sites-enabled/ten64.<site>.mithis.com-http-local.conf

# Remove the Debian default site (conflicts with port 443)
sudo rm -f /etc/nginx/sites-enabled/00-default
```

**Important:** The `status.txt` file must be writable by the `www-data`
user. The stream Lua health checker writes to it periodically.

### Enable a site

```bash
# Symlink the per-host directory
sudo ln -s /etc/nginx/gdoc2netcfg/sites-available/<fqdn> \
           /etc/nginx/sites-enabled/<fqdn>

# Test and reload
sudo nginx -t
sudo systemctl reload nginx
```

The symlink activates all three aspects of the site simultaneously:
- `http-proxy.conf` is picked up by `include sites-enabled/*/http-*.conf`
- `https-upstream.conf` is picked up by `include sites-enabled/*/https-upstream.conf` (inside `00-https`)
- `https-map.conf` is picked up by `include sites-enabled/*/https-map.conf` (inside `00-https`)
- Lua healthcheck files (`http-healthcheck.lua`, `https-healthcheck.lua`)
  are scanned by the `init_worker_by_lua_block` in the healthcheck setup configs

### Disable a site

```bash
sudo rm /etc/nginx/sites-enabled/<fqdn>
sudo nginx -t
sudo systemctl reload nginx
```

Note: `reload` creates new worker processes that pick up the updated
`init_worker_by_lua_block` glob results. However, if the Lua `io.popen`
glob ran before the symlink was removed, old workers may still run
healthchecks for the removed site until they exit. A full `restart`
ensures a clean slate.

## Updating configs

When the spreadsheet data changes or the generator code is updated:

```bash
cd /opt/gdoc2netcfg
sudo uv run gdoc2netcfg fetch
sudo uv run gdoc2netcfg generate nginx

# Wipe and replace generated configs
sudo rm -rf /etc/nginx/gdoc2netcfg/sites-available \
            /etc/nginx/gdoc2netcfg/conf.d \
            /etc/nginx/gdoc2netcfg/stream.d \
            /etc/nginx/gdoc2netcfg/scripts
sudo cp -a nginx/* /etc/nginx/gdoc2netcfg/

# Fix status.txt ownership (recreated by cp)
sudo touch /etc/nginx/gdoc2netcfg/status.txt
sudo chown www-data:www-data /etc/nginx/gdoc2netcfg/status.txt

sudo nginx -t
sudo systemctl restart nginx
```

The `sites-enabled/` symlinks remain intact because they point into
`sites-available/` which is replaced in-place. A full restart (not reload)
is recommended after replacing healthcheck Lua files.

## Monitoring

### Status endpoints

```bash
# HTTP upstream health (Lua resty healthcheck status page)
curl http://ten64.<site>.mithis.com/status-http

# HTTPS upstream health (TCP connect probe results)
curl http://ten64.<site>.mithis.com/status-https
```

### What the status shows

**HTTP status** (via `lua-resty-upstream-healthcheck`):
- Combined upstreams actively probe each backend every 5 seconds on port 80
- Backends marked DOWN after 3 consecutive failures, UP after 2 successes
- Per-interface upstreams show `(NO checkers)` — they always report UP

**HTTPS status** (via custom `checker.lua`):
- Combined upstreams actively probe each backend every 5 seconds on port 443
- Uses TCP connect probes (not TLS handshake) since backends may not serve HTTPS
- Per-interface upstreams show `(NO checkers)` — status display only

### Error log

```bash
sudo tail -f /var/log/nginx/error.log
```

Expected messages for hosts with unreachable interfaces:
- `healthcheck: failed to connect to <ip>:80: timeout` — HTTP health check failure
- `connect() failed (113: No route to host)` — HTTPS stream proxy to unreachable backend

These are normal for multi-interface hosts where one interface is down.
The failover mechanism ensures traffic routes to healthy interfaces.

## Architecture notes

### Why stream SNI passthrough?

The HTTPS architecture uses stream-level SNI passthrough rather than
HTTP-module HTTPS blocks. This means nginx **never terminates TLS** for
proxied hosts — it reads the SNI field from the TLS ClientHello and
forwards the raw TCP connection to the appropriate backend.

Benefits:
- Backends manage their own TLS certificates
- No certificate management needed on the nginx gateway for proxied hosts
- End-to-end encryption between client and backend
- Consistent behaviour for both IPv4 (proxied) and IPv6 (direct) paths

### Multi-interface hosts

Hosts with multiple network interfaces (e.g. eth0 + wlan0) get:
- A **combined upstream** with Lua-based health-aware peer selection
- **Per-interface upstreams** for direct access via interface-specific FQDNs
- Lua health check files that register with the checker framework

The combined upstream uses `balancer_by_lua_file` in the stream context
to select healthy peers, falling back across interfaces transparently.

### Port layout

| Port | Binding                | Module | Purpose                                    |
|------|------------------------|--------|--------------------------------------------|
| 80   | `0.0.0.0` / `[::]`     | http   | HTTP reverse proxy for all sites           |
| 443  | `0.0.0.0` / `[::]`     | stream | TLS SNI multiplexer (no TLS termination)   |
| 8443 | `127.0.0.1` / `[::1]`  | http   | Local HTTPS fallback (TLS terminated here) |
| 8080 | `127.0.0.1`            | http   | Healthcheck status page (localhost only)   |
