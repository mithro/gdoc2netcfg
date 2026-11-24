"""nginx reverse proxy configuration generator.

Produces per-host nginx config directories under sites-available/.
Each host gets a directory containing:

  - http-proxy.conf           HTTP reverse proxy (port 80)
  - https-upstream.conf       TLS passthrough upstream (stream context)
  - https-map.conf            SNI map entries for TLS routing

HTTPS is handled via stream SNI passthrough rather than http-module
HTTPS blocks, ensuring consistent TLS behavior for both IPv4 (proxied)
and IPv6 (direct) paths. HTTP blocks include inline ACME challenge
locations with try_files fallback to the backend.

Multi-interface hosts get a combined HTTP config file containing:

  - An upstream block listing all interface IPs for round-robin failover
  - A root server block using the upstream with proxy_next_upstream
    on error/timeout/502, with hostname-level DNS names
  - A server block per named interface using direct proxy_pass to
    that interface's IP, with interface-specific DNS names

Single-interface hosts produce a simple direct proxy_pass config
(no upstream block).

Admins activate configs via symlinks in sites-enabled/.
"""

from __future__ import annotations

from typing import NamedTuple

from gdoc2netcfg.models.host import DNSName, Host, NetworkInventory
from gdoc2netcfg.utils.dns import is_safe_dns_name, is_safe_path


class _UpstreamInfo(NamedTuple):
    """Metadata for a generated upstream block, used for healthcheck config."""

    name: str       # e.g. "tweed.welland.mithis.com-http-backend"
    host: str       # e.g. "tweed.welland.mithis.com"


def _is_nginx_name(dn: DNSName) -> bool:
    """Check if a DNS name should appear in nginx configs.

    Excludes IPv6-only names (ipv4 is None) since nginx proxies to
    IPv4 backends, and names with unsafe characters.
    """
    return dn.ipv4 is not None and is_safe_dns_name(dn.name)


def _partition_dns_names(
    host: Host,
) -> tuple[list[DNSName], dict[str, list[DNSName]]]:
    """Partition a host's DNS names into root and per-interface groups.

    Returns (root_names, iface_names) where:
      - root_names: DNS names not specific to any named interface
      - iface_names: dict mapping interface name → list of DNS names

    A DNS name belongs to an interface group if it contains
    "{iface_name}.{hostname}" — this matches Pass 2 names and their
    Pass 3/4 derivatives.
    """
    named_ifaces = [iface for iface in host.interfaces if iface.name]

    if not named_ifaces:
        return list(host.dns_names), {}

    iface_names: dict[str, list[DNSName]] = {
        iface.name: [] for iface in named_ifaces
    }
    root_names: list[DNSName] = []

    for dn in host.dns_names:
        matched = False
        for iface in named_ifaces:
            marker = f"{iface.name}.{host.hostname}"
            if marker in dn.name:
                iface_names[iface.name].append(dn)
                matched = True
                break
        if not matched:
            root_names.append(dn)

    return root_names, iface_names


def _upstream_block(upstream_name: str, ips: list[str], port: int = 80) -> str:
    """Generate an nginx upstream block for failover.

    Lists all IPs as equal-weight servers for round-robin with
    automatic failure detection. Port specifies the backend port.
    """
    lines = [f"upstream {upstream_name} {{"]
    for ip in ips:
        lines.append(f"    server {ip}:{port};")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _https_upstream_block(
    upstream_name: str,
    ips: list[str],
    balancer_lua_path: str = "",
) -> str:
    """Generate an HTTPS upstream block for TLS passthrough.

    Single-interface hosts get a direct server entry.
    Multi-interface hosts use a placeholder server with
    balancer_by_lua_file for health-aware peer selection.
    """
    lines = [f"upstream {upstream_name} {{"]
    if balancer_lua_path:
        # Multi-interface: placeholder IP, Lua balancer selects real peer
        lines.append("    server 0.0.0.1:443;  # placeholder")
        lines.append(f"    balancer_by_lua_file {balancer_lua_path};")
    else:
        for ip in ips:
            lines.append(f"    server {ip}:443;")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _https_map_entries(
    upstream_name: str,
    dns_names: list[str],
) -> str:
    """Generate bare SNI map entries for a host.

    Each line maps a DNS name to the host's HTTPS upstream. These are
    included by the admin's hand-crafted map block via:
        include /etc/nginx/sites-enabled/*/https-map.conf;

    Wildcard alt-names (``*.example.com``) are emitted verbatim as ``*.``
    keys. They only match if that hand-crafted map declares ``hostnames;``;
    without it nginx compares them as literal strings and the name falls
    through to ``default`` without any error. See the ``00-https`` template
    in docs/nginx-deployment.md and issue #101.
    """
    lines = []
    for name in dns_names:
        # Pad to align the upstream name (nginx map syntax: key value;)
        lines.append(f"{name} {upstream_name};")
    lines.append("")
    return "\n".join(lines)


def _emit_https_files(
    files: dict[str, str],
    primary_fqdn: str,
    fqdn_names: list[str],
    ips: list[str],
    balancer_lua_path: str = "",
) -> None:
    """Emit HTTPS upstream and SNI map files for a host.

    fqdn_names must be FQDN-only (not bare hostnames) because SNI
    values in TLS ClientHello are always fully qualified domain names.
    """
    upstream_name = f"{primary_fqdn}-https-backend"

    files[f"sites-available/{primary_fqdn}/https-upstream.conf"] = _https_upstream_block(
        upstream_name, ips, balancer_lua_path=balancer_lua_path,
    )
    files[f"sites-available/{primary_fqdn}/https-map.conf"] = _https_map_entries(
        upstream_name, fqdn_names,
    )


def _emit_combined_https_files(
    files: dict[str, str],
    primary_fqdn: str,
    root_fqdn_names: list[str],
    all_ips: list[str],
    iface_configs: list[tuple[list[str], str, str]],
    balancer_lua_path: str,
) -> None:
    """Emit HTTPS upstream and SNI map files for a multi-interface host.

    Like the HTTP combined config, generates a combined upstream for the
    root hostname (with balancer_by_lua_file for health-aware peer selection)
    plus per-interface direct upstreams. The SNI map routes root FQDN names
    to the combined upstream and interface-specific names to their direct
    upstream.
    """
    upstream_name = f"{primary_fqdn}-https-backend"

    # Combined upstream with balancer
    parts = [_https_upstream_block(upstream_name, all_ips, balancer_lua_path=balancer_lua_path)]

    # Per-interface direct upstreams
    for _iface_fqdn_names, iface_ip, iface_fqdn in iface_configs:
        iface_upstream = f"{iface_fqdn}-https-backend"
        parts.append(_https_upstream_block(iface_upstream, [iface_ip]))

    files[f"sites-available/{primary_fqdn}/https-upstream.conf"] = "\n".join(parts)

    # Map entries: root names → combined, interface names → direct
    map_parts = [_https_map_entries(upstream_name, root_fqdn_names)]
    for iface_fqdn_names, _iface_ip, iface_fqdn in iface_configs:
        iface_upstream = f"{iface_fqdn}-https-backend"
        map_parts.append(_https_map_entries(iface_upstream, iface_fqdn_names))

    files[f"sites-available/{primary_fqdn}/https-map.conf"] = "".join(map_parts)


def generate_nginx(
    inventory: NetworkInventory,
    acme_webroot: str = "/var/www/acme",
    lua_healthcheck_path: str = "/usr/share/lua/5.1/",
    gdoc2netcfg_dir: str = "/etc/nginx/gdoc2netcfg",
    sites_enabled_dir: str = "/etc/nginx/sites-enabled",
) -> dict[str, str]:
    """Generate nginx reverse proxy configs for each host.

    Returns a dict mapping relative paths to file contents.

    Args:
        lua_healthcheck_path: Base directory for lua-resty-upstream-healthcheck.
            Used to set lua_package_path in nginx config.
        gdoc2netcfg_dir: Deployment root for all generated nginx files.
            Used to derive runtime paths for balancer_by_lua_file,
            lua_package_path (scripts/), and status file.
        sites_enabled_dir: Where nginx loads enabled site configs from.
            Used by init_worker blocks to scan for healthcheck lua files
            via glob pattern {sites_enabled_dir}/*/http-healthcheck.lua.

    Raises:
        ValueError: If acme_webroot, lua_healthcheck_path,
            gdoc2netcfg_dir, or sites_enabled_dir contain unsafe characters.
    """
    if not is_safe_path(acme_webroot):
        raise ValueError(f"Unsafe acme_webroot path: {acme_webroot!r}")
    if not is_safe_path(lua_healthcheck_path):
        raise ValueError(f"Unsafe lua_healthcheck_path: {lua_healthcheck_path!r}")
    if not is_safe_path(gdoc2netcfg_dir):
        raise ValueError(f"Unsafe gdoc2netcfg_dir: {gdoc2netcfg_dir!r}")
    if not is_safe_path(sites_enabled_dir):
        raise ValueError(f"Unsafe sites_enabled_dir: {sites_enabled_dir!r}")

    files: dict[str, str] = {}
    healthcheck_hosts: list[tuple[str, list[_UpstreamInfo]]] = []
    # Active (upstream_name, fqdn, ips) + passive [(upstream_name, fqdn, ip), ...]
    https_healthcheck_hosts: list[
        tuple[str, str, list[str], list[tuple[str, str, str]]]
    ] = []

    for host in inventory.hosts_sorted():
        fqdns = [
            dn.name for dn in host.dns_names
            if dn.is_fqdn and _is_nginx_name(dn)
        ]
        if not fqdns:
            continue

        # All nginx-eligible names (including bare hostnames) for HTTP server_name
        all_nginx_names = [
            dn.name for dn in host.dns_names
            if _is_nginx_name(dn)
        ]
        # FQDN-only subset for HTTPS SNI map (TLS ClientHello uses FQDNs)
        all_fqdn_names = [
            dn.name for dn in host.dns_names
            if dn.is_fqdn and _is_nginx_name(dn)
        ]

        if not host.is_multi_interface():
            # Single-interface host
            primary_fqdn = fqdns[0]
            target_ip = str(host.virtual_interfaces[0].ipv4)

            _emit_http_files(
                files, primary_fqdn, all_nginx_names, target_ip,
                acme_webroot,
            )
            _emit_https_files(
                files, primary_fqdn, all_fqdn_names,
                ips=[target_ip],
            )
        else:
            # Multi-interface host: single file per variant containing
            # upstream block + root server block + per-interface server blocks
            root_dns, iface_dns = _partition_dns_names(host)

            root_fqdns = [
                dn.name for dn in root_dns
                if dn.is_fqdn and _is_nginx_name(dn)
            ]
            if not root_fqdns:
                continue

            primary_fqdn = root_fqdns[0]
            root_names = [
                dn.name for dn in root_dns
                if _is_nginx_name(dn)
            ]

            all_ips = [
                str(vi.ipv4) for vi in host.virtual_interfaces
            ]

            # Collect per-interface config tuples:
            #   http_configs: (all_names, ip, first_fqdn) for HTTP server blocks
            #   https_configs: (fqdn_names, ip, first_fqdn) for HTTPS SNI routing
            iface_http_configs: list[tuple[list[str], str, str]] = []
            iface_https_configs: list[tuple[list[str], str, str]] = []
            for iface in host.interfaces:
                if iface.name is None:
                    continue
                dns_for_iface = iface_dns.get(iface.name, [])
                iface_fqdns = [
                    dn.name for dn in dns_for_iface
                    if dn.is_fqdn and _is_nginx_name(dn)
                ]
                iface_names = [
                    dn.name for dn in dns_for_iface
                    if _is_nginx_name(dn)
                ]
                if not iface_names or not iface_fqdns:
                    continue
                iface_http_configs.append(
                    (iface_names, str(iface.ipv4), iface_fqdns[0])
                )
                iface_https_configs.append(
                    (iface_fqdns, str(iface.ipv4), iface_fqdns[0])
                )

            _emit_combined_http_files(
                files, primary_fqdn, root_names,
                all_ips, iface_http_configs,
                acme_webroot,
            )
            balancer_path = f"{gdoc2netcfg_dir}/sites-available/{primary_fqdn}/https-balancer.lua"

            _emit_combined_https_files(
                files, primary_fqdn, root_fqdns,
                all_ips, iface_https_configs,
                balancer_lua_path=balancer_path,
            )

            # Collect upstream metadata for per-host healthcheck config
            upstream_name = f"{primary_fqdn}-http-backend"
            host_upstreams = [_UpstreamInfo(
                name=upstream_name,
                host=primary_fqdn,
            )]
            healthcheck_hosts.append((primary_fqdn, host_upstreams))

            # Collect HTTPS healthcheck metadata: active combined upstream
            # plus passive per-interface entries for status display.
            # Per-interface upstreams have a single peer so health checking
            # them is pointless — there is no failover decision to make.
            passive: list[tuple[str, str, str]] = []
            for _iface_fqdn_names, iface_ip, iface_fqdn in iface_https_configs:
                passive.append(
                    (f"{iface_fqdn}-https-backend", iface_fqdn, iface_ip)
                )
            https_healthcheck_hosts.append(
                (f"{primary_fqdn}-https-backend", primary_fqdn, all_ips, passive)
            )

    # Emit healthcheck config files if any multi-interface hosts exist
    if healthcheck_hosts:
        files["conf.d/healthcheck-setup.conf"] = _http_healthcheck_setup_conf(
            lua_healthcheck_path, sites_enabled_dir,
        )
        files["conf.d/healthcheck-status.conf"] = _healthcheck_status_conf()
        for fqdn, upstreams in healthcheck_hosts:
            files[f"sites-available/{fqdn}/http-healthcheck.lua"] = _healthcheck_host_lua(upstreams)

    # Emit HTTPS health check files if any multi-interface hosts exist
    if https_healthcheck_hosts:
        files["stream.d/healthcheck-setup.conf"] = (
            _https_healthcheck_setup_conf(gdoc2netcfg_dir, sites_enabled_dir)
        )
        files["scripts/checker.lua"] = _https_checker_lua()
        for upstream_name, fqdn, ips, passive_upstreams in https_healthcheck_hosts:
            files[f"sites-available/{fqdn}/https-healthcheck.lua"] = (
                _https_healthcheck_host_lua(
                    upstream_name, fqdn, ips, passive_upstreams,
                )
            )
            files[f"sites-available/{fqdn}/https-balancer.lua"] = (
                _https_balancer_lua(upstream_name)
            )

    return files


def _emit_http_files(
    files: dict[str, str],
    primary_fqdn: str,
    all_names: list[str],
    target_ip: str,
    acme_webroot: str = "/var/www/acme",
) -> None:
    """Emit the HTTP config file for a single-interface host."""
    files[f"sites-available/{primary_fqdn}/http-proxy.conf"] = _http_block(
        all_names, target_ip, acme_webroot=acme_webroot,
    )


def _emit_combined_http_files(
    files: dict[str, str],
    primary_fqdn: str,
    root_names: list[str],
    all_ips: list[str],
    iface_configs: list[tuple[list[str], str, str]],
    acme_webroot: str = "/var/www/acme",
) -> None:
    """Emit one HTTP config file for a multi-interface host.

    The file contains upstream blocks (a round-robin failover upstream
    for the root, plus one single-server upstream per interface named by
    its FQDN), the root server block, and one server block per named
    interface.
    """
    upstream_name = f"{primary_fqdn}-http-backend"
    upstream_text = _upstream_block(upstream_name, all_ips, port=80)
    parts = [upstream_text]

    # Per-interface upstream blocks (single server, named by FQDN)
    for _iface_names, iface_ip, iface_fqdn in iface_configs:
        iface_upstream = f"{iface_fqdn}-http-backend"
        parts.append(
            _upstream_block(iface_upstream, [iface_ip], port=80)
        )

    # Root server block (upstream failover)
    parts.append(_http_block(
        root_names, "",
        acme_webroot=acme_webroot,
        upstream_name=upstream_name,
    ))

    # Per-interface server blocks (proxy_pass via named upstream)
    for iface_names, _iface_ip, iface_fqdn in iface_configs:
        iface_upstream = f"{iface_fqdn}-http-backend"
        parts.append(_http_block(
            iface_names, "",
            acme_webroot=acme_webroot,
            upstream_name=iface_upstream,
        ))

    files[f"sites-available/{primary_fqdn}/http-proxy.conf"] = "\n".join(parts)



def _server_names(names: list[str]) -> str:
    """Format the server_name directive."""
    return " ".join(names)


def _acme_challenge_block(
    acme_webroot: str,
    proxy_target: str,
) -> list[str]:
    """Generate ACME challenge location blocks with fallback proxy.

    Returns lines for two locations within an HTTP server block:
    1. A primary location that tries serving from disk first
    2. A named fallback location that proxies to the backend

    The try_files directive serves local challenge files (for certbot
    running on this nginx host) and falls back to proxying the request
    to the backend (for backends that handle their own ACME challenges).
    """
    return [
        "    location /.well-known/acme-challenge/ {",
        f"        root {acme_webroot};",
        "        auth_basic off;",
        "        try_files $uri @acme_fallback;",
        "    }",
        "",
        "    location @acme_fallback {",
        f"        proxy_pass http://{proxy_target};",
        "        proxy_http_version 1.1;",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
        "    }",
    ]


def _http_block(
    names: list[str],
    target_ip: str,
    acme_webroot: str = "/var/www/acme",
    upstream_name: str = "",
) -> str:
    """Generate an HTTP (port 80) server block.

    When upstream_name is set, proxy_pass targets the upstream and
    proxy_next_upstream is added for failover.
    """
    proxy_target = upstream_name if upstream_name else target_ip
    lines = [
        "server {",
        "    listen 80;",
        "    listen [::]:80;",
        f"    server_name {_server_names(names)};",
        "",
    ]

    lines.extend(_acme_challenge_block(acme_webroot, proxy_target))
    lines.append("")

    lines.append("    location / {")

    if upstream_name:
        lines.append(f"        proxy_pass http://{upstream_name};")
        lines.append("        proxy_next_upstream error timeout http_502;")
    else:
        lines.append(f"        proxy_pass http://{target_ip};")

    lines.extend([
        "        proxy_http_version 1.1;",
        '        proxy_set_header Upgrade $http_upgrade;',
        '        proxy_set_header Connection "upgrade";',
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
        "    }",
        "}",
        "",
    ])
    return "\n".join(lines)


def _http_healthcheck_setup_conf(lua_path: str, sites_enabled_dir: str) -> str:
    """Generate the combined HTTP healthcheck setup config.

    Merges lua_package_path, shared memory zone, socket error suppression,
    and the init_worker_by_lua_block into a single conf.d/ file.

    The init_worker block scans {sites_enabled_dir}/*/http-healthcheck.lua
    for per-host healthcheck configs. Per-host files contain their own
    upstream existence guards, so files for disabled hosts are safely
    skipped at runtime.
    """
    scan_pattern = f"{sites_enabled_dir}/*/http-healthcheck.lua"
    return (
        f"lua_package_path \"{lua_path}?.lua;{lua_path}?/init.lua;;\";\n"
        "lua_shared_dict healthcheck 1m;\n"
        "# NB: lua_socket_log_errors is a global setting — it suppresses\n"
        "# socket errors for ALL Lua modules, not just healthcheck probes.\n"
        "lua_socket_log_errors off;\n"
        "\n"
        "init_worker_by_lua_block {\n"
        f'    local pipe = io.popen("ls {scan_pattern}")\n'
        "    if not pipe then return end\n"
        "    for path in pipe:lines() do\n"
        "        local fn, err = loadfile(path)\n"
        "        if fn then\n"
        "            local ok, exec_err = pcall(fn)\n"
        "            if not ok then\n"
        '                ngx.log(ngx.ERR, "healthcheck config error in ", '
        "path, \": \", exec_err)\n"
        "            end\n"
        "        else\n"
        '            ngx.log(ngx.ERR, "failed to load ", path, ": ", err)\n'
        "        end\n"
        "    end\n"
        "    pipe:close()\n"
        "}\n"
    )


def _healthcheck_host_lua(upstreams: list[_UpstreamInfo]) -> str:
    """Generate a per-host Lua file with spawn_checker calls.

    Each file is self-contained: it requires the healthcheck and upstream
    modules, defines a try_spawn helper that checks upstream existence
    before spawning, then calls it for each variant.

    The upstream existence check (get_primary_peers) means this file can
    be deployed permanently — if the host's server config isn't enabled
    (not symlinked into sites-enabled/), the upstreams won't exist and
    the spawn calls are silently skipped.
    """
    lines = [
        'local hc = require "resty.upstream.healthcheck"',
        'local upstream_mod = require "ngx.upstream"',
        "",
        "local function try_spawn(opts)",
        "    if not upstream_mod.get_primary_peers(opts.upstream) then",
        "        return",
        "    end",
        "    local ok, err = hc.spawn_checker(opts)",
        "    if not ok then",
        '        ngx.log(ngx.ERR, "failed to spawn health checker for ",'
        " opts.upstream, \": \", err)",
        "    end",
        "end",
        "",
    ]

    for us in upstreams:
        lines.append("try_spawn({")
        checker_args = [
            'shm = "healthcheck"',
            f'upstream = "{us.name}"',
            'type = "http"',
            f'http_req = "GET / HTTP/1.0\\r\\nHost: {us.host}\\r\\n\\r\\n"',
            "interval = 5000",
            "timeout = 2000",
            "fall = 3",
            "rise = 2",
            # Omit valid_statuses: when nil, lua-resty-upstream-healthcheck
            # skips status code validation — any HTTP response means the
            # backend is alive. Only connection failures mark it down.
        ]
        for arg in checker_args:
            lines.append(f"    {arg},")
        lines.append("})")
        lines.append("")

    return "\n".join(lines)


def _https_healthcheck_setup_conf(
    gdoc2netcfg_dir: str,
    sites_enabled_dir: str,
) -> str:
    """Generate the combined HTTPS healthcheck setup config.

    Merges lua_package_path, shared memory zone, socket error suppression,
    and the init_worker_by_lua_block into a single stream.d/ file.

    The init_worker block scans {sites_enabled_dir}/*/https-healthcheck.lua
    for per-host healthcheck configs. Unlike HTTP healthchecks (which use
    ngx.upstream.get_primary_peers() to detect whether an upstream exists),
    stream upstreams have no equivalent API. Only hosts symlinked into
    sites-enabled/ get their healthcheck lua loaded.
    """
    scripts_dir = f"{gdoc2netcfg_dir}/scripts"
    status_file = f"{gdoc2netcfg_dir}/status.txt"
    scan_pattern = f"{sites_enabled_dir}/*/https-healthcheck.lua"
    return (
        f'lua_package_path "{scripts_dir}/?.lua;;";\n'
        "lua_shared_dict stream_healthcheck 1m;\n"
        "lua_socket_log_errors off;\n"
        "\n"
        "init_worker_by_lua_block {\n"
        '    local checker = require "checker"\n'
        f'    checker.set_status_file("{status_file}")\n'
        f'    local pipe = io.popen("ls {scan_pattern}")\n'
        "    if not pipe then\n"
        "        checker.start()\n"
        "        return\n"
        "    end\n"
        "    for path in pipe:lines() do\n"
        "        local fn, err = loadfile(path)\n"
        "        if fn then\n"
        "            local ok, exec_err = pcall(fn)\n"
        "            if not ok then\n"
        '                ngx.log(ngx.ERR, "https healthcheck config error in ", '
        "path, \": \", exec_err)\n"
        "            end\n"
        "        else\n"
        '            ngx.log(ngx.ERR, "failed to load ", path, ": ", err)\n'
        "        end\n"
        "    end\n"
        "    pipe:close()\n"
        "    checker.start()\n"
        "}\n"
    )


def _https_healthcheck_host_lua(
    upstream_name: str,
    fqdn: str,
    ips: list[str],
    passive_upstreams: list[tuple[str, str, str]] = (),
) -> str:
    """Generate a per-host Lua file for HTTPS health checking.

    Registers the combined upstream for active health checking.
    Per-interface upstreams are registered passively — they appear in
    status output with ``(NO checkers)`` but are not probed, since they
    have a single peer and no failover decision to make.
    """
    lines = [
        'local checker = require "checker"',
        "",
        "checker.register({",
        f'    upstream = "{upstream_name}",',
        f'    host = "{fqdn}",',
        "    peers = {",
    ]
    for ip in ips:
        lines.append(f'        "{ip}",')
    lines.extend([
        "    },",
        "    interval = 5,",
        "    timeout = 2,",
        "    fall = 3,",
        "    rise = 2,",
        "})",
        "",
    ])
    for p_upstream, p_fqdn, p_ip in passive_upstreams:
        lines.extend([
            "checker.register_passive({",
            f'    upstream = "{p_upstream}",',
            f'    host = "{p_fqdn}",',
            f'    peer = "{p_ip}",',
            "})",
            "",
        ])
    return "\n".join(lines)


def _https_checker_lua() -> str:
    """Generate the shared checker.lua module for HTTPS health checks.

    This module:
    1. Maintains a registry of upstreams and their peers
    2. Uses ngx.timer.every to probe each peer on port 443
    3. Uses TCP connect to verify backend is accepting connections
    4. Tracks consecutive failures (fall) and recoveries (rise)
    5. Stores health status in lua_shared_dict stream_healthcheck
    6. Writes status to a file for the HTTP status endpoint
    """
    return '''\
local _M = {}

local registry = {}
local passive_registry = {}
local upstream_order = {}
local shm = ngx.shared.stream_healthcheck
local status_file = nil

function _M.set_status_file(path)
    status_file = path
end

function _M.register(opts)
    registry[opts.upstream] = {
        host = opts.host,
        peers = opts.peers,
        interval = opts.interval or 5,
        timeout = opts.timeout or 2,
        fall = opts.fall or 3,
        rise = opts.rise or 2,
    }
    upstream_order[#upstream_order + 1] = opts.upstream
    -- Initialise health state: start DOWN (pessimistic).
    -- Peers must pass `rise` consecutive checks before being marked UP.
    -- This avoids showing all peers as UP before any check has run.
    for _, ip in ipairs(opts.peers) do
        local key = opts.upstream .. ":" .. ip
        if not shm:get(key .. ":init") then
            shm:set(key .. ":init", true)
            shm:set(key .. ":healthy", false)
            shm:set(key .. ":fail_count", 0)
            shm:set(key .. ":ok_count", 0)
        end
    end
end

function _M.register_passive(opts)
    -- Display-only: appears in status output with (NO checkers)
    -- but is not health-checked.  Used for single-peer upstreams
    -- where there is no failover decision to make.
    passive_registry[opts.upstream] = {
        host = opts.host,
        peer = opts.peer,
    }
    upstream_order[#upstream_order + 1] = opts.upstream
end

local function check_peer(upstream_name, info, ip)
    local sock = ngx.socket.tcp()
    sock:settimeout(info.timeout * 1000)

    local ok, err = sock:connect(ip, 443)
    if ok then
        sock:close()
    end

    -- TCP connect success = backend is accepting connections on port 443
    return ok, err
end

local function update_peer(upstream_name, info, ip, healthy)
    local key = upstream_name .. ":" .. ip

    if healthy then
        shm:set(key .. ":fail_count", 0)
        local ok_count = (shm:get(key .. ":ok_count") or 0) + 1
        shm:set(key .. ":ok_count", ok_count)
        if ok_count >= info.rise then
            shm:set(key .. ":healthy", true)
        end
    else
        shm:set(key .. ":ok_count", 0)
        local fail_count = (shm:get(key .. ":fail_count") or 0) + 1
        shm:set(key .. ":fail_count", fail_count)
        if fail_count >= info.fall then
            shm:set(key .. ":healthy", false)
        end
    end
end

local function write_status()
    if not status_file then return end
    local lines = {}
    for _, upstream_name in ipairs(upstream_order) do
        local info = registry[upstream_name]
        local pinfo = passive_registry[upstream_name]
        if info then
            lines[#lines + 1] = "Upstream " .. upstream_name
            lines[#lines + 1] = "    Primary Peers"
            for _, ip in ipairs(info.peers) do
                local key = upstream_name .. ":" .. ip
                local healthy = shm:get(key .. ":healthy")
                local status = healthy and "UP" or "DOWN"
                lines[#lines + 1] = "        " .. ip .. ":443 " .. status
            end
            lines[#lines + 1] = ""
        elseif pinfo then
            lines[#lines + 1] = "Upstream " .. upstream_name .. " (NO checkers)"
            lines[#lines + 1] = "    Primary Peers"
            lines[#lines + 1] = "        " .. pinfo.peer .. ":443 UP"
            lines[#lines + 1] = ""
        end
    end
    local f = io.open(status_file, "w")
    if f then
        f:write(table.concat(lines, "\\n") .. "\\n")
        f:close()
    end
end

local function run_checks()
    -- Spawn all peer checks concurrently using lightweight threads.
    -- Each ngx.thread runs as a coroutine on the nginx event loop,
    -- so connect timeouts don't block other checks.
    local threads = {}
    local thread_meta = {}  -- {upstream_name, info, ip} per thread

    for upstream_name, info in pairs(registry) do
        for _, ip in ipairs(info.peers) do
            local th, err = ngx.thread.spawn(check_peer, upstream_name, info, ip)
            if th then
                threads[#threads + 1] = th
                thread_meta[#thread_meta + 1] = {upstream_name, info, ip}
            else
                -- spawn failed: treat as check failure
                ngx.log(ngx.WARN, "thread spawn failed for ", ip, ": ", err)
                update_peer(upstream_name, info, ip, false)
            end
        end
    end

    -- Wait for all threads and collect results
    for i, th in ipairs(threads) do
        local ok, healthy, _ = ngx.thread.wait(th)
        local meta = thread_meta[i]
        if ok then
            update_peer(meta[1], meta[2], meta[3], healthy)
        else
            -- thread aborted
            update_peer(meta[1], meta[2], meta[3], false)
        end
    end

    write_status()
end

function _M.start()
    local min_interval = 5
    for _, info in pairs(registry) do
        if info.interval < min_interval then
            min_interval = info.interval
        end
    end
    -- Write initial status before first check cycle
    write_status()
    ngx.timer.every(min_interval, function(premature)
        if premature then return end
        run_checks()
    end)
end

function _M.get_healthy_peer(upstream_name)
    local info = registry[upstream_name]
    if not info then return nil, "unknown upstream" end

    -- Round-robin across healthy peers using a shared counter
    local rr_key = upstream_name .. ":rr_index"
    local rr_index = (shm:get(rr_key) or 0)
    local n = #info.peers

    for i = 1, n do
        local idx = ((rr_index + i - 1) % n) + 1
        local ip = info.peers[idx]
        local key = upstream_name .. ":" .. ip
        if shm:get(key .. ":healthy") then
            shm:set(rr_key, idx)
            return ip
        end
    end

    -- All peers down: round-robin as fallback
    local idx = (rr_index % n) + 1
    shm:set(rr_key, idx)
    return info.peers[idx], "all peers unhealthy"
end

return _M
'''


def _https_balancer_lua(upstream_name: str) -> str:
    """Generate a per-host balancer Lua file for balancer_by_lua_file.

    Each multi-interface host gets its own balancer file with the
    upstream name hardcoded. This avoids the problem of trying to
    discover the upstream name at runtime in the HTTPS balancer
    context, where nginx variables like ngx.var.upstream_name are
    not available.
    """
    return f'''\
local checker = require "checker"
local balancer = require "ngx.balancer"

local peer, err = checker.get_healthy_peer("{upstream_name}")
if not peer then
    ngx.log(ngx.ERR, "no healthy peer for https upstream {upstream_name}: ", err)
    return ngx.exit(502)
end

local ok, set_err = balancer.set_current_peer(peer, 443)
if not ok then
    ngx.log(ngx.ERR, "failed to set https peer: ", set_err)
    return ngx.exit(502)
end
'''


def _healthcheck_status_conf() -> str:
    """Generate the healthcheck status monitoring endpoint.

    Listens on 127.0.0.1:8080 (localhost only) and exposes the
    healthcheck status page at /upstream-status.
    """
    return (
        "server {\n"
        "    listen 127.0.0.1:8080;\n"
        "\n"
        "    location /upstream-status {\n"
        "        default_type text/plain;\n"
        "        content_by_lua_block {\n"
        "            local hc = require \"resty.upstream.healthcheck\"\n"
        "            ngx.say(hc.status_page())\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
