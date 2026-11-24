"""Tests for the nginx reverse proxy generator."""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.nginx import generate_nginx
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import (
    Host,
    NetworkInterface,
    NetworkInventory,
)
from gdoc2netcfg.models.network import IPv6Prefix, Site

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={
        8: "int", 9: "int", 10: "int", 11: "int",
        12: "int", 13: "int", 14: "int", 15: "int",
        90: "iot",
    },
)


def _make_host(hostname="desktop", ip="10.1.10.100"):
    ipv4 = IPv4Address(ip)
    parts = ip.split(".")
    aa = parts[1]
    bb = parts[2].zfill(2)
    ccc = parts[3]
    ipv6 = IPv6Address(f"2404:e80:a137:{aa}{bb}::{ccc}", "2404:e80:a137:")

    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ip_addresses=(ipv4, ipv6),
                dhcp_name=hostname,
            ),
        ],
    )
    derive_all_dns_names(host, SITE)
    return host


def _make_inventory(*hosts):
    return NetworkInventory(site=SITE, hosts=list(hosts))


class TestNginxFileStructure:
    def test_produces_three_site_files_per_host(self):
        """Each host gets 1 HTTP + 2 HTTPS files."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        site_files = [k for k in files if k.startswith("sites-available/")]
        assert len(site_files) == 3

        assert f"sites-available/{fqdn}/http-proxy.conf" in site_files
        assert f"sites-available/{fqdn}/https-upstream.conf" in site_files
        assert f"sites-available/{fqdn}/https-map.conf" in site_files

    def test_https_files_are_stream_not_http(self):
        """HTTPS files are stream upstream/map, not http-module blocks."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        https_files = [k for k in files if "https" in k and k.startswith("sites-available/")]
        assert len(https_files) == 2
        assert any("https-upstream" in f for f in https_files)
        assert any("https-map" in f for f in https_files)

    def test_host_with_no_fqdns_skipped(self):
        host = Host(
            machine_name="local",
            hostname="local",
            interfaces=[
                NetworkInterface(
                    name=None,
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                    ip_addresses=(IPv4Address("192.168.1.1"),),
                    dhcp_name="local",
                ),
            ],
        )
        files = generate_nginx(_make_inventory(host))

        # No sites-available files for non-FQDN hosts
        site_files = [k for k in files if k.startswith("sites-available/")]
        assert len(site_files) == 0


class TestHTTPBlock:
    def test_http_public_has_listen_80(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "listen 80;" in block
        assert "listen [::]:80;" in block

    def test_http_public_has_server_name(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "desktop.welland.mithis.com" in block
        assert "desktop.int.welland.mithis.com" in block
        assert "server_name" in block

    def test_ipv6_only_names_excluded(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "ipv4.desktop.welland.mithis.com" in block
        assert "ipv6.desktop.welland.mithis.com" not in block

    def test_http_public_has_proxy_pass(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "proxy_pass http://10.1.10.100;" in block

    def test_http_public_no_auth_in_main_location(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        # auth_basic "Restricted" should NOT appear (that's the private variant)
        assert 'auth_basic "Restricted"' not in block
        # auth_basic off IS present in the ACME challenge block
        assert "auth_basic off;" in block

    def test_http_public_no_auth_basic(self):
        """HTTP block should not have auth_basic (backends handle their own auth)."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert 'auth_basic "Restricted"' not in block
        assert "auth_basic_user_file" not in block

    def test_http_has_inline_acme_with_try_files(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "location /.well-known/acme-challenge/" in block
        assert "root /var/www/acme;" in block
        assert "auth_basic off;" in block
        assert "try_files $uri @acme_fallback;" in block

    def test_http_has_acme_fallback_proxy(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "location @acme_fallback {" in block
        assert "proxy_pass http://10.1.10.100;" in block

    def test_http_has_proxy_headers(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "proxy_set_header Host $host;" in block
        assert "proxy_set_header X-Real-IP $remote_addr;" in block
        assert "proxy_set_header X-Forwarded-For" in block
        assert "proxy_set_header X-Forwarded-Proto" in block

    def test_http_has_websocket_headers(self):
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "proxy_http_version 1.1;" in block
        assert "proxy_set_header Upgrade $http_upgrade;" in block
        assert 'proxy_set_header Connection "upgrade";' in block


class TestAcmeFallback:
    def test_fallback_proxy_has_headers(self):
        """@acme_fallback location has standard proxy headers."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        # Find the fallback section
        fallback_start = block.index("@acme_fallback")
        fallback = block[fallback_start:]
        assert "proxy_set_header Host $host;" in fallback
        assert "proxy_set_header X-Real-IP $remote_addr;" in fallback
        assert "proxy_set_header X-Forwarded-For" in fallback
        assert "proxy_set_header X-Forwarded-Proto" in fallback

    def test_custom_webroot_in_acme_block(self):
        """Custom acme_webroot flows through to inline ACME block."""
        host = _make_host()
        files = generate_nginx(
            _make_inventory(host), acme_webroot="/srv/acme",
        )

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "root /srv/acme;" in block

    def test_multi_interface_fallback_uses_upstream(self):
        """Multi-interface hosts use upstream name in ACME fallback."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        block = files[f"sites-available/{fqdn}/http-proxy.conf"]
        fallback_start = block.index("@acme_fallback")
        fallback = block[fallback_start:]
        # Should proxy to the upstream, not a bare IP
        assert f"proxy_pass http://{fqdn}-http-backend;" in fallback

    def test_no_include_snippet_in_http_block(self):
        """HTTP blocks no longer use include for ACME — it's inline."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "include snippets/acme-challenge.conf;" not in block


class TestMultipleHosts:
    def test_two_hosts_produce_six_site_files(self):
        h1 = _make_host(hostname="desktop", ip="10.1.10.100")
        h2 = _make_host(hostname="server", ip="10.1.10.200")
        files = generate_nginx(_make_inventory(h1, h2))

        site_files = [k for k in files if k.startswith("sites-available/")]
        assert len(site_files) == 6  # 3 per host (1 HTTP + 2 HTTPS)

    def test_each_host_uses_own_ip(self):
        h1 = _make_host(hostname="desktop", ip="10.1.10.100")
        h2 = _make_host(hostname="server", ip="10.1.10.200")
        files = generate_nginx(_make_inventory(h1, h2))

        desktop_http = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "proxy_pass http://10.1.10.100;" in desktop_http

        server_http = files["sites-available/server.welland.mithis.com/http-proxy.conf"]
        assert "proxy_pass http://10.1.10.200;" in server_http


def _make_multi_iface_host(
    hostname="rpi-sdr-kraken",
    iface_ips=None,
):
    """Create a host with multiple named interfaces.

    iface_ips is a dict of {interface_name: ip_string}.
    """
    if iface_ips is None:
        iface_ips = {"eth0": "10.1.90.149", "wlan0": "10.1.90.150"}

    interfaces = []
    for i, (iface_name, ip) in enumerate(iface_ips.items()):
        ipv4 = IPv4Address(ip)
        parts = ip.split(".")
        aa = parts[1]
        bb = parts[2].zfill(2)
        ccc = parts[3]
        ipv6 = IPv6Address(f"2404:e80:a137:{aa}{bb}::{ccc}", "2404:e80:a137:")

        interfaces.append(
            NetworkInterface(
                name=iface_name,
                mac=MACAddress.parse(f"aa:bb:cc:dd:ee:{i:02x}"),
                ip_addresses=(ipv4, ipv6),
                dhcp_name=f"{iface_name}-{hostname}",
            ),
        )

    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=interfaces,
    )
    derive_all_dns_names(host, SITE)
    return host


def _extract_server_blocks(config_text: str) -> list[str]:
    """Extract individual server { ... } blocks from a config file."""
    blocks = []
    depth = 0
    current: list[str] = []
    for line in config_text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("server {"):
            depth = 1
            current = [line]
        elif depth > 0:
            current.append(line)
            depth += stripped.count("{") - stripped.count("}")
            if depth == 0:
                blocks.append("\n".join(current))
                current = []
    return blocks


class TestMultiInterfaceHost:
    def test_produces_six_site_files(self):
        """Multi-interface hosts produce 1 HTTP + 2 HTTPS + 3 healthcheck lua files."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        site_files = [k for k in files if k.startswith("sites-available/")]
        assert len(site_files) == 6
        assert f"sites-available/{fqdn}/http-proxy.conf" in site_files
        assert f"sites-available/{fqdn}/https-upstream.conf" in site_files
        assert f"sites-available/{fqdn}/https-map.conf" in site_files
        assert f"sites-available/{fqdn}/http-healthcheck.lua" in site_files
        assert f"sites-available/{fqdn}/https-healthcheck.lua" in site_files
        assert f"sites-available/{fqdn}/https-balancer.lua" in site_files

    def test_file_contains_upstream_block(self):
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        conf = files["sites-available/rpi-sdr-kraken.welland.mithis.com/http-proxy.conf"]
        assert "upstream rpi-sdr-kraken.welland.mithis.com-http-backend {" in conf
        assert "server 10.1.90.149:80;" in conf
        assert "server 10.1.90.150:80;" in conf

    def test_file_contains_three_server_blocks(self):
        """Each file has root + eth0 + wlan0 server blocks."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        conf = files["sites-available/rpi-sdr-kraken.welland.mithis.com/http-proxy.conf"]
        blocks = _extract_server_blocks(conf)
        assert len(blocks) == 3

    def test_root_server_block_uses_upstream(self):
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        conf = files["sites-available/rpi-sdr-kraken.welland.mithis.com/http-proxy.conf"]
        blocks = _extract_server_blocks(conf)
        root_block = blocks[0]
        expected = "proxy_pass http://rpi-sdr-kraken.welland.mithis.com-http-backend;"
        assert expected in root_block
        assert "proxy_next_upstream error timeout http_502;" in root_block

    def test_root_server_block_has_only_root_names(self):
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        conf = files["sites-available/rpi-sdr-kraken.welland.mithis.com/http-proxy.conf"]
        blocks = _extract_server_blocks(conf)
        root_block = blocks[0]
        assert "rpi-sdr-kraken.welland.mithis.com" in root_block
        assert "eth0.rpi-sdr-kraken" not in root_block
        assert "wlan0.rpi-sdr-kraken" not in root_block

    def test_interface_server_blocks_use_named_upstream(self):
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        conf = files[f"sites-available/{fqdn}/http-proxy.conf"]
        blocks = _extract_server_blocks(conf)
        eth0_block = blocks[1]
        wlan0_block = blocks[2]

        # Per-interface blocks use named upstreams, not bare IPs
        assert f"proxy_pass http://eth0.{fqdn}-http-backend;" in eth0_block
        assert f"proxy_pass http://wlan0.{fqdn}-http-backend;" in wlan0_block

    def test_interface_server_blocks_have_interface_names(self):
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        conf = files["sites-available/rpi-sdr-kraken.welland.mithis.com/http-proxy.conf"]
        blocks = _extract_server_blocks(conf)
        eth0_block = blocks[1]
        wlan0_block = blocks[2]

        assert "eth0.rpi-sdr-kraken.welland.mithis.com" in eth0_block
        assert "wlan0.rpi-sdr-kraken.welland.mithis.com" in wlan0_block

    def test_single_interface_host_unchanged(self):
        """Single-interface hosts should not produce upstream blocks."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "upstream" not in block
        assert "proxy_next_upstream" not in block
        assert "proxy_pass http://10.1.10.100;" in block

class TestAltNames:
    def test_alt_names_in_server_name(self):
        host = _make_host()
        host.alt_names = ["alias.example.com"]
        derive_all_dns_names(host, SITE)
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "alias.example.com" in block

    def test_wildcard_alt_names_in_server_name(self):
        host = _make_host()
        host.alt_names = ["*.example.com"]
        derive_all_dns_names(host, SITE)
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "*.example.com" in block

    def test_wildcard_alt_names_kept_verbatim_in_https_map(self):
        """A `*.` alt-name becomes a `*.` SNI map key, not a regex.

        The key only matches when the hand-written map that includes
        https-map.conf declares `hostnames;` (docs/nginx-deployment.md,
        issue #101). Without it nginx compares the key as a literal string
        and the name silently falls through to `default`.
        """
        host = _make_host()
        host.alt_names = ["*.example.com"]
        derive_all_dns_names(host, SITE)
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        https_map = files[f"sites-available/{fqdn}/https-map.conf"]
        assert f"*.example.com {fqdn}-https-backend;" in https_map.splitlines()

    def test_multiple_alt_names(self):
        host = _make_host()
        host.alt_names = ["a.example.com", "b.example.com"]
        derive_all_dns_names(host, SITE)
        files = generate_nginx(_make_inventory(host))

        block = files["sites-available/desktop.welland.mithis.com/http-proxy.conf"]
        assert "a.example.com" in block
        assert "b.example.com" in block


class TestPathValidation:
    def test_rejects_malicious_acme_webroot(self):
        import pytest

        host = _make_host()
        with pytest.raises(ValueError, match="Unsafe acme_webroot"):
            generate_nginx(
                _make_inventory(host),
                acme_webroot="/var/www/acme; rm -rf /",
            )



class TestSharedIPHost:
    """Tests for hosts with multiple NICs sharing the same IP address."""

    def test_shared_ip_treated_as_single_interface(self):
        """Two NICs with same IP should produce single-interface config (no upstream)."""
        host = _make_multi_iface_host(
            hostname="roku",
            iface_ips={"eth0": "10.1.90.50", "wlan0": "10.1.90.50"},
        )
        files = generate_nginx(_make_inventory(host))

        fqdn = "roku.welland.mithis.com"
        site_files = [k for k in files if k.startswith("sites-available/")]
        assert len(site_files) == 3  # 1 HTTP + 2 stream

        # Should use direct proxy_pass, not upstream
        http_pub = files[f"sites-available/{fqdn}/http-proxy.conf"]
        assert "upstream" not in http_pub
        assert "proxy_pass http://10.1.90.50;" in http_pub

    def test_shared_ip_no_duplicate_upstream_entries(self):
        """If shared-IP host is somehow multi-interface, IPs should be unique."""
        # Create a host with 3 NICs: eth0+wlan0 on same IP, eth1 on different IP
        host = _make_multi_iface_host(
            hostname="server",
            iface_ips={"eth0": "10.1.10.100", "wlan0": "10.1.10.100", "eth1": "10.1.10.101"},
        )
        files = generate_nginx(_make_inventory(host))

        fqdn = "server.welland.mithis.com"
        http_pub = files[f"sites-available/{fqdn}/http-proxy.conf"]
        # Extract the main round-robin upstream block (first one)
        main_upstream_end = http_pub.index("}\n\n")
        main_upstream = http_pub[:main_upstream_end]
        # Main upstream should have two entries, not three
        assert main_upstream.count("server 10.1.10.100:80;") == 1
        assert main_upstream.count("server 10.1.10.101:80;") == 1


class TestHealthcheck:
    """Tests for lua-resty-upstream-healthcheck config generation."""

    def test_no_healthcheck_files_for_single_interface_only(self):
        """No conf.d/ or healthcheck lua files when only single-interface hosts."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        confd_files = [k for k in files if k.startswith("conf.d/")]
        hc_lua_files = [k for k in files if k.endswith("http-healthcheck.lua")]
        assert len(confd_files) == 0
        assert len(hc_lua_files) == 0

    def test_healthcheck_files_present_for_multi_interface_host(self):
        """conf.d/ files and per-host .lua emitted for multi-interface host."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        assert "conf.d/healthcheck-setup.conf" in files
        assert "conf.d/healthcheck-status.conf" in files
        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        assert f"sites-available/{fqdn}/http-healthcheck.lua" in files

    def test_healthcheck_setup_has_default_lua_path(self):
        """Default lua_package_path uses /usr/share/lua/5.1/."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        conf = files["conf.d/healthcheck-setup.conf"]
        assert "lua_package_path" in conf
        assert "/usr/share/lua/5.1/" in conf

    def test_healthcheck_setup_has_custom_lua_path(self):
        """Custom lua_healthcheck_path flows through to lua_package_path."""
        host = _make_multi_iface_host()
        files = generate_nginx(
            _make_inventory(host),
            lua_healthcheck_path="/opt/lua/lib/",
        )

        conf = files["conf.d/healthcheck-setup.conf"]
        assert "/opt/lua/lib/" in conf

    def test_rejects_unsafe_lua_healthcheck_path(self):
        """Path injection in lua_healthcheck_path is rejected."""
        import pytest

        host = _make_multi_iface_host()
        with pytest.raises(ValueError, match="Unsafe lua_healthcheck_path"):
            generate_nginx(
                _make_inventory(host),
                lua_healthcheck_path="/opt/lua'; evil;",
            )

    def test_per_host_lua_has_one_http_variant(self):
        """Per-host .lua file contains spawn_checker for single HTTP upstream."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        lua = files[f"sites-available/{fqdn}/http-healthcheck.lua"]
        assert f"{fqdn}-http-backend" in lua
        assert "https" not in lua

    def test_separate_lua_files_per_host(self):
        """Each multi-interface host gets its own .lua file."""
        h1 = _make_multi_iface_host(
            hostname="host-a",
            iface_ips={"eth0": "10.1.90.10", "eth1": "10.1.90.11"},
        )
        h2 = _make_multi_iface_host(
            hostname="host-b",
            iface_ips={"eth0": "10.1.90.20", "eth1": "10.1.90.21"},
        )
        files = generate_nginx(_make_inventory(h1, h2))

        # Separate per-host .lua files
        assert "sites-available/host-a.welland.mithis.com/http-healthcheck.lua" in files
        assert "sites-available/host-b.welland.mithis.com/http-healthcheck.lua" in files
        # Single merged setup conf with init_worker (no host-specific content)
        setup = files["conf.d/healthcheck-setup.conf"]
        assert setup.count("init_worker_by_lua_block") == 1
        assert "host-a" not in setup
        assert "host-b" not in setup

    def test_setup_conf_scans_sites_enabled(self):
        """Setup conf has init_worker that scans sites-enabled for healthcheck lua."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        setup = files["conf.d/healthcheck-setup.conf"]
        assert "init_worker_by_lua_block" in setup
        assert "sites-enabled" in setup
        assert "http-healthcheck.lua" in setup
        assert "loadfile" in setup

    def test_setup_conf_custom_sites_enabled_dir(self):
        """Custom sites_enabled_dir flows through to setup conf."""
        host = _make_multi_iface_host()
        files = generate_nginx(
            _make_inventory(host),
            sites_enabled_dir="/opt/nginx/enabled",
        )

        setup = files["conf.d/healthcheck-setup.conf"]
        assert "/opt/nginx/enabled" in setup

    def test_rejects_unsafe_sites_enabled_dir(self):
        """Path injection in sites_enabled_dir is rejected."""
        import pytest

        host = _make_multi_iface_host()
        with pytest.raises(ValueError, match="Unsafe sites_enabled_dir"):
            generate_nginx(
                _make_inventory(host),
                sites_enabled_dir="/etc/nginx/hc'; rm -rf /;",
            )

    def test_per_host_lua_checks_upstream_exists(self):
        """Per-host .lua file guards against missing upstreams."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        lua = files[f"sites-available/{fqdn}/http-healthcheck.lua"]
        assert "get_primary_peers" in lua

    def test_status_conf_has_listener_and_endpoint(self):
        """Status page config has correct listener and endpoint."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        status = files["conf.d/healthcheck-status.conf"]
        assert "127.0.0.1:8080" in status
        assert "/upstream-status" in status
        assert "status_page" in status

    def test_healthcheck_lua_omits_valid_statuses(self):
        """valid_statuses is omitted so any HTTP response means healthy."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        lua = files[f"sites-available/{fqdn}/http-healthcheck.lua"]
        assert "valid_statuses" not in lua

    def test_mixed_hosts_only_multi_interface_in_healthcheck(self):
        """Single-interface hosts are excluded from healthcheck files."""
        single = _make_host(hostname="desktop", ip="10.1.10.100")
        multi = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(single, multi))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        assert f"sites-available/{fqdn}/http-healthcheck.lua" in files
        hc_lua_files = [k for k in files if k.endswith("http-healthcheck.lua")]
        assert len(hc_lua_files) == 1  # only the multi-interface host

    def test_shared_ip_host_no_healthcheck(self):
        """Shared-IP hosts (treated as single-interface) don't trigger healthcheck."""
        shared = _make_multi_iface_host(
            hostname="roku",
            iface_ips={"eth0": "10.1.90.50", "wlan0": "10.1.90.50"},
        )
        files = generate_nginx(_make_inventory(shared))

        confd_files = [k for k in files if k.startswith("conf.d/")]
        hc_lua_files = [k for k in files if k.endswith("http-healthcheck.lua")]
        assert len(confd_files) == 0
        assert len(hc_lua_files) == 0


class TestHTTPSSNI:
    """Tests for HTTPS SNI passthrough config generation."""

    def test_per_host_https_upstream_file(self):
        """Each host gets a sites-available/{fqdn}/https-upstream.conf file."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        assert f"sites-available/{fqdn}/https-upstream.conf" in files

    def test_per_host_https_map_file(self):
        """Each host gets a sites-available/{fqdn}/https-map.conf file."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        assert f"sites-available/{fqdn}/https-map.conf" in files

    def test_single_host_https_upstream(self):
        """Single-interface host gets direct server entry in HTTPS upstream."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        upstream = files[f"sites-available/{fqdn}/https-upstream.conf"]
        assert f"upstream {fqdn}-https-backend {{" in upstream
        assert "server 10.1.10.100:443;" in upstream
        assert "balancer_by_lua_file" not in upstream

    def test_multi_interface_https_upstream_has_balancer(self):
        """Multi-interface host uses balancer_by_lua_file in HTTPS upstream."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        upstream = files[f"sites-available/{fqdn}/https-upstream.conf"]
        assert f"upstream {fqdn}-https-backend {{" in upstream
        assert "server 0.0.0.1:443;" in upstream
        assert "balancer_by_lua_file" in upstream

    def test_multi_interface_https_has_per_interface_upstreams(self):
        """Multi-interface hosts get per-interface direct HTTPS upstreams."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        upstream = files[f"sites-available/{fqdn}/https-upstream.conf"]
        # Per-interface upstreams with direct server entries
        assert f"upstream eth0.{fqdn}-https-backend {{" in upstream
        assert "server 10.1.90.149:443;" in upstream
        assert f"upstream wlan0.{fqdn}-https-backend {{" in upstream
        assert "server 10.1.90.150:443;" in upstream

    def test_multi_interface_https_map_routes_interfaces_to_direct_upstream(self):
        """Interface-specific SNI names route to direct per-interface HTTPS upstreams."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        https_map = files[f"sites-available/{fqdn}/https-map.conf"]
        # Root names → combined upstream with balancer
        assert f"rpi-sdr-kraken.welland.mithis.com {fqdn}-https-backend;" in https_map
        # Interface names → direct per-interface upstream
        assert f"eth0.{fqdn} eth0.{fqdn}-https-backend;" in https_map
        assert f"wlan0.{fqdn} wlan0.{fqdn}-https-backend;" in https_map

    def test_https_map_entries_for_all_fqdns(self):
        """HTTPS map file has entries for all FQDN DNS names."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        https_map = files[f"sites-available/{fqdn}/https-map.conf"]
        # Root FQDN and subdomain variant
        assert f"desktop.welland.mithis.com {fqdn}-https-backend;" in https_map
        assert f"desktop.int.welland.mithis.com {fqdn}-https-backend;" in https_map
        # ipv4 prefix variant
        assert f"ipv4.desktop.welland.mithis.com {fqdn}-https-backend;" in https_map

    def test_no_ipv6_only_names_in_https_map(self):
        """IPv6-only DNS names are excluded from HTTPS map."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        https_map = files[f"sites-available/{fqdn}/https-map.conf"]
        assert "ipv6.desktop.welland.mithis.com" not in https_map

    def test_no_bare_hostnames_in_https_map(self):
        """Bare (non-FQDN) hostnames excluded from HTTPS map (SNI is always FQDN)."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "desktop.welland.mithis.com"
        https_map = files[f"sites-available/{fqdn}/https-map.conf"]
        # "desktop" without domain should not appear as its own map entry
        for line in https_map.strip().splitlines():
            name = line.split()[0]
            assert "." in name, f"bare hostname in HTTPS map: {name}"

    def test_healthcheck_lua_only_http_variant(self):
        """HTTP health check .lua files have single HTTP variant, not HTTPS."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        lua = files[f"sites-available/{fqdn}/http-healthcheck.lua"]
        # 1 try_spawn call (http-backend) + 1 function def
        assert lua.count("try_spawn({\n") == 1
        # upstream name says "http-backend", not "https"
        assert f"{fqdn}-http-backend" in lua


class TestHTTPSHealthcheck:
    """Tests for custom HTTPS health checker for TLS passthrough upstreams."""

    def test_no_https_healthcheck_for_single_interface(self):
        """Single-interface hosts don't generate HTTPS health check files."""
        host = _make_host()
        files = generate_nginx(_make_inventory(host))

        stream_d = [k for k in files if k.startswith("stream.d/")]
        https_hc = [k for k in files if k.endswith(("https-healthcheck.lua", "https-balancer.lua"))]
        scripts = [k for k in files if k.startswith("scripts/")]
        assert len(stream_d) == 0
        assert len(https_hc) == 0
        assert len(scripts) == 0

    def test_https_healthcheck_setup_generated(self):
        """Multi-interface host triggers merged stream.d/ healthcheck setup."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        assert "stream.d/healthcheck-setup.conf" in files
        setup = files["stream.d/healthcheck-setup.conf"]
        assert "lua_shared_dict stream_healthcheck" in setup
        assert "lua_package_path" in setup
        assert "init_worker_by_lua_block" in setup
        # Scans sites-enabled for HTTPS healthcheck lua files
        assert "sites-enabled" in setup
        assert "https-healthcheck.lua" in setup
        # Sets status file path for health status output
        assert "set_status_file" in setup
        assert "status.txt" in setup

    def test_https_per_host_lua_in_host_dir(self):
        """Per-host HTTPS health check Lua files are in host directory."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        key = f"sites-available/{fqdn}/https-healthcheck.lua"
        assert key in files
        lua = files[key]
        assert "10.1.90.149" in lua
        assert "10.1.90.150" in lua
        assert f"{fqdn}-https-backend" in lua

    def test_https_healthcheck_registers_combined_and_passive_interfaces(self):
        """Combined upstream gets active health checks; per-interface get passive display."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        lua = files[f"sites-available/{fqdn}/https-healthcheck.lua"]
        # Combined upstream registered with active health checks
        assert lua.count("checker.register(") == 1
        assert f'upstream = "{fqdn}-https-backend"' in lua
        assert "10.1.90.149" in lua
        assert "10.1.90.150" in lua
        # Per-interface upstreams registered passively for status display
        assert lua.count("checker.register_passive(") == 2
        assert f'upstream = "eth0.{fqdn}-https-backend"' in lua
        assert f'upstream = "wlan0.{fqdn}-https-backend"' in lua

    def test_https_checker_lua_generated(self):
        """Shared checker.lua module is generated at top level."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        assert "scripts/checker.lua" in files
        checker = files["scripts/checker.lua"]
        assert "sock:connect" in checker
        assert "stream_healthcheck" in checker
        # Has status file writing for the HTTP status endpoint
        assert "write_status" in checker
        assert "set_status_file" in checker
        # Peers start DOWN (pessimistic) — must prove healthy via rise checks
        # The register function sets initial state to false
        register_func = checker.split("function _M.register")[1].split("\nend")[0]
        assert ':healthy", false)' in register_func
        assert ':healthy", true)' not in register_func
        # Uses concurrent threads for checking peers
        assert "ngx.thread.spawn" in checker
        assert "ngx.thread.wait" in checker
        # Has register_passive for display-only upstreams
        assert "function _M.register_passive" in checker
        # Passive upstreams shown with (NO checkers) in status
        assert "(NO checkers)" in checker

    def test_per_host_balancer_lua_generated(self):
        """Each multi-interface host gets its own balancer with hardcoded upstream name."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        key = f"sites-available/{fqdn}/https-balancer.lua"
        assert key in files
        balancer = files[key]
        assert f"{fqdn}-https-backend" in balancer
        assert "set_current_peer" in balancer

    def test_https_upstream_references_per_host_balancer(self):
        """Multi-interface HTTPS upstream references per-host balancer via gdoc2netcfg_dir."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        upstream = files[f"sites-available/{fqdn}/https-upstream.conf"]
        assert f"/etc/nginx/gdoc2netcfg/sites-available/{fqdn}/https-balancer.lua" in upstream

    def test_https_healthcheck_custom_dirs(self):
        """Custom gdoc2netcfg_dir and sites_enabled_dir flow through."""
        host = _make_multi_iface_host()
        files = generate_nginx(
            _make_inventory(host),
            gdoc2netcfg_dir="/opt/nginx/gen",
            sites_enabled_dir="/opt/nginx/enabled",
        )

        setup = files["stream.d/healthcheck-setup.conf"]
        # lua_package_path uses gdoc2netcfg_dir/scripts/
        assert "/opt/nginx/gen/scripts" in setup
        # init_worker scans sites_enabled_dir for HTTPS healthcheck lua
        assert "/opt/nginx/enabled" in setup
        # status file uses gdoc2netcfg_dir
        assert "/opt/nginx/gen/status.txt" in setup

        fqdn = "rpi-sdr-kraken.welland.mithis.com"
        upstream = files[f"sites-available/{fqdn}/https-upstream.conf"]
        # balancer_by_lua_file uses gdoc2netcfg_dir
        assert f"/opt/nginx/gen/sites-available/{fqdn}/https-balancer.lua" in upstream

    def test_no_shared_balancer_lua(self):
        """No shared balancer.lua — each host gets its own per-host balancer."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        assert "scripts/balancer.lua" not in files

    def test_rejects_unsafe_gdoc2netcfg_dir(self):
        """Path injection in gdoc2netcfg_dir is rejected."""
        import pytest

        host = _make_multi_iface_host()
        with pytest.raises(ValueError, match="Unsafe gdoc2netcfg_dir"):
            generate_nginx(
                _make_inventory(host),
                gdoc2netcfg_dir="/etc/nginx/hc'; rm -rf /;",
            )

    def test_checker_lua_has_round_robin(self):
        """get_healthy_peer uses round-robin, not always first healthy."""
        host = _make_multi_iface_host()
        files = generate_nginx(_make_inventory(host))

        checker = files["scripts/checker.lua"]
        assert "rr_index" in checker or "round" in checker.lower()
