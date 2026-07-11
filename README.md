# gdoc2netcfg

Generate network infrastructure configuration files from Google Spreadsheet data.

`gdoc2netcfg` reads device records (machine names, MAC addresses, IPs, interfaces) from published Google Sheets CSVs and produces configuration files for dnsmasq (internal and external split-horizon DNS, DHCP), Nagios, nginx, and Let's Encrypt.

## Quick start

```bash
# Install dependencies
uv sync

# Fetch spreadsheet data (caches locally)
uv run gdoc2netcfg fetch

# Generate all config files
uv run gdoc2netcfg generate --output-dir /etc/gdoc2netcfg/

# Generate to stdout for inspection
uv run gdoc2netcfg generate --stdout dnsmasq_internal

# Validate data without generating
uv run gdoc2netcfg validate

# Scan SSH fingerprints for SSHFP records
uv run gdoc2netcfg sshfp --force
```

## How it works

The tool runs a six-stage pipeline:

1. **Sources** -- fetch CSVs from Google Sheets, cache locally, parse into device records
2. **Derivations** -- pure functions that compute IPv6 addresses, VLAN membership, hostnames, DHCP names, DNS names, and default IPs
3. **Supplements** -- external enrichment (SSHFP scanning via `ssh-keyscan`, SSL certificate scanning)
4. **Constraints** -- validation checks (field presence, BMC placement, MAC uniqueness, IPv6 consistency)
5. **Generators** -- produce output config files (dnsmasq, nagios, nginx, letsencrypt)
6. **Config files** -- per-host `.conf` files written to output directories

See [docs/architecture.md](docs/architecture.md) for details.

## Configuration

Copy the example template and edit for your site:

```bash
cp gdoc2netcfg.toml.example gdoc2netcfg.toml
```

`gdoc2netcfg.toml` is gitignored — each site keeps its own untracked copy. The tracked `gdoc2netcfg.toml.example` contains Welland defaults and comments marking site-specific fields.

Settings:

- `[site]` -- domain name, public IPv4 (site-specific)
- `[sheets]` -- Google Sheets published CSV URLs
- `[ipv6]` -- IPv6 prefix list for dual-stack address generation
- `[vlans]` and `[network_subdomains]` -- VLAN topology and subdomain mappings
- `[generators]` -- which generators to enable and their output directories (site-specific)

## Output format

The dnsmasq generators produce one `.conf` file per host. Each file contains:

- **DHCP bindings** (`dhcp-host=`) with IPv4 and IPv6 addresses
- **PTR records** (`ptr-record=`) for IPv4 and IPv6 reverse DNS
- **Forward DNS** (`host-record=`) with subdomain variants and `ipv4.`/`ipv6.` prefix variants
- **CAA records** (`dns-rr=` type 257) for Let's Encrypt
- **SSHFP records** (`dns-rr=` type 44) for SSH fingerprint verification

The external dnsmasq generator implements split-horizon DNS by replacing RFC 1918 addresses with the site's public IPv4.

The nginx generator produces per-host reverse proxy server blocks under `sites-available/`, with four variants per host (`http-public`, `http-private`, `https-public`, `https-private`). Multi-interface hosts get an `upstream` block for round-robin failover across all interfaces, plus per-interface server blocks with direct `proxy_pass`. HTTP variants proxy to port 80, HTTPS variants to port 443.

The gwifi generators (welland only) read the "Google WiFi Pucks" tab: `gwifi_pucks` emits `wisp/pucks.json` — the gale puck identity file for the netboot-install service on wisp.welland.mithis.com (deploy: `scp wisp/pucks.json wisp.welland.mithis.com:/tmp/ && ssh wisp.welland.mithis.com 'sudo install -m 0644 /tmp/pucks.json /etc/gwifi-netboot/pucks.json && sudo systemctl restart gwifi-netboot'`) — and `gwifi_pucks_dns` emits `internal/gwifi-pucks-dns.conf` (puck host-records for ten64's dnsmasq, deployed by the normal `make deploy-dnsmasq-internal`). See `gwifi-openwrt` `docs/wisp-netboot-install-design.md`.

## Development

```bash
uv run pytest                    # Run tests
uv run pytest -x                 # Stop on first failure
uv run ruff check src/ tests/    # Lint
```

## Licence

Apache 2.0
