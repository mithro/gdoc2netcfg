# Nginx stream SSL setup on welland

The welland gateway (`ten64.welland.mithis.com`) uses nginx's `stream` module with `ssl_preread` to multiplex HTTPS traffic on port 443 between local welland sites and the remote monarto site, without terminating TLS.

## Problem

Both `*.welland.mithis.com` and `*.monarto.mithis.com` need to be served over HTTPS on the same public IP (87.121.95.37). Welland's nginx terminates TLS for welland sites using Let's Encrypt certs, but monarto traffic must pass through untouched so monarto's own nginx can terminate TLS with its own certs.

Standard nginx `http` server blocks cannot do this -- by the time an `http` block sees the request, TLS has already been terminated. The `stream` module operates at the TCP layer and can inspect the TLS ClientHello SNI field without decrypting the connection.

## Architecture

```
Internet
    │
    ▼
┌──────────────────────────────────────────────┐
│  nginx stream module (port 443)              │
│  ssl_preread extracts SNI from ClientHello   │
│                                              │
│  SNI matches *.monarto.mithis.com?           │
│    YES → raw TCP proxy to 10.2.0.1:443 ─────────► monarto nginx (terminates TLS)
│    NO  → forward to 127.0.0.1:8443 ─────┐   │
└──────────────────────────────────────────│───┘
                                           │
                                           ▼
                              ┌─────────────────────────┐
                              │  nginx http module       │
                              │  port 127.0.0.1:8443    │
                              │  terminates TLS          │
                              │  reverse proxies to      │
                              │  backend hosts           │
                              └─────────────────────────┘
```

HTTP traffic (port 80) is unaffected -- it goes directly to the `http` module as usual. A separate `http` server block proxies `*.monarto.mithis.com` HTTP requests to monarto.

## Port layout

| Port | Binding | Module | Purpose |
|------|---------|--------|---------|
| 80 | `0.0.0.0` / `[::]` | http | HTTP for all sites |
| 443 | `0.0.0.0` / `[::]` | stream | TLS SNI multiplexer (no TLS termination) |
| 8443 | `127.0.0.1` / `[::1]` | http | Local HTTPS (TLS terminated here) |

## Configuration files

### `/etc/nginx/nginx.conf`

The `stream` block is at the top level, alongside `http`:

```nginx
http {
    # ... standard http config ...
    include /etc/nginx/sites-enabled/*;
}

stream {
    include /etc/nginx/stream.d/*.conf;
}
```

The `stream` module is loaded via `/etc/nginx/modules-enabled/` (package `libnginx-mod-stream`).

### `/etc/nginx/stream.d/00-monarto-forward.conf`

SNI-based routing:

```nginx
map $ssl_preread_server_name $tls_upstream {
    ~\.monarto\.mithis\.com$    monarto_https;
    monarto.mithis.com          monarto_https;
    default                     local_https;
}

upstream monarto_https {
    server 10.2.0.1:443;
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

`ssl_preread on` tells nginx to read the TLS ClientHello to extract the SNI server name, which populates `$ssl_preread_server_name`. The `map` directive routes to the appropriate upstream. No TLS termination occurs in the stream block -- the raw TCP bytes are forwarded as-is.

### `/etc/nginx/sites-available/00-default`

The catch-all listens on both HTTP and the local HTTPS port:

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

### `/etc/nginx/sites-available/monarto-forward`

HTTP proxy for monarto (HTTPS is handled by the stream module):

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name ~\.monarto\.mithis\.com$ monarto.mithis.com;

    location / {
        proxy_pass http://10.2.0.1;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        # ... other proxy headers ...
    }
}
```

### HTTPS site configs (`*-https-public`, `*-https-private`)

All HTTPS site configs listen on `127.0.0.1:8443` instead of `443`:

```nginx
server {
    listen 127.0.0.1:8443 ssl;
    listen [::1]:8443 ssl;
    server_name tweed.welland.mithis.com;

    ssl_certificate /etc/letsencrypt/live/tweed.welland.mithis.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tweed.welland.mithis.com/privkey.pem;
    # ...
}
```

## HTTPS listen configuration

The nginx generator supports an `https_listen` parameter in `gdoc2netcfg.toml` that controls the HTTPS listen directives. On welland, this is set to `127.0.0.1:8443` so generated HTTPS configs bind to the loopback address where the stream module forwards local TLS traffic:

```toml
[generators.nginx]
https_listen = "127.0.0.1:8443"
```

This produces:

```nginx
listen 127.0.0.1:8443 ssl;
listen [::1]:8443 ssl;
```

If `https_listen` is omitted, the default `listen 443 ssl` / `listen [::]:443 ssl` is used (suitable for sites without stream SSL multiplexing).

## Adding a new site to the stream multiplexer

To route a new site's HTTPS traffic elsewhere (e.g. a third site), add entries to the `map` in `00-monarto-forward.conf`:

```nginx
map $ssl_preread_server_name $tls_upstream {
    ~\.monarto\.mithis\.com$    monarto_https;
    monarto.mithis.com          monarto_https;
    ~\.newsite\.mithis\.com$    newsite_https;
    newsite.mithis.com          newsite_https;
    default                     local_https;
}

upstream newsite_https {
    server <newsite-wireguard-ip>:443;
}
```

Then add a corresponding HTTP proxy server block in `sites-available/` for the new site's HTTP traffic.

The regex keys above (`~\.newsite\.mithis\.com$`) match as they are. If you
use the shorter `*.newsite.mithis.com` form instead (which is what the nginx
generator writes for wildcard alt-names in `https-map.conf`), the map **must**
declare `hostnames;`, or the key is compared as a literal string and never
matches. See "Why `hostnames;` is required" in
[nginx-deployment.md](nginx-deployment.md).

## Troubleshooting

**Port 443 bind conflict during restart**: If `nginx -t` passes but `systemctl restart nginx` fails with "Address already in use" for port 443, old worker processes may still hold the port. Use `sudo systemctl stop nginx`, wait for workers to exit, then `sudo systemctl start nginx`.

**Monarto HTTPS not working**: Verify the WireGuard tunnel is up (`ping 10.2.0.1`) and that monarto's nginx is listening on port 443. The stream module forwards raw TCP, so any TLS errors are between the client and monarto's nginx, not welland's.

**Welland HTTPS returning wrong cert**: If a client sends no SNI (e.g. connecting by IP), traffic goes to `default` → `local_https` → `127.0.0.1:8443`, where the `00-default` server block returns 444 using the snakeoil cert. If a *subdomain* of a `*.domain` map entry gets the gateway's cert while the bare domain works, the map is missing `hostnames;`: without it, map keys are matched as exact strings (or as regexes with `~`), and `*.` keys are literal text that never matches.
