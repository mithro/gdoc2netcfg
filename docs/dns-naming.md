# DNS Naming and Reverse DNS

How gdoc2netcfg derives DNS names from spreadsheet data, generates dnsmasq
forward/reverse DNS records, and validates forward-confirmed reverse DNS.

## Overview

Each host in the spreadsheet gets a set of DNS names derived from its hostname,
interface names, VLAN membership, and address families. These names are generated
by five composable derivation passes, then emitted as dnsmasq `host-record`,
`ptr-record`, and `dns-rr` config lines.

The key design goals:

- **Every IP resolves to the most-specific name** — `ipv4.eth0.server.int.welland.mithis.com` rather than `server.welland.mithis.com`
- **Bare hostnames resolve to all IPs** — round-robin DNS for multi-homed hosts
- **Split-horizon DNS** — internal uses RFC 1918 addresses, external substitutes the site's public IPv4
- **Forward-confirmed reverse DNS (FCrDNS)** — every PTR name has a matching forward record


## Name derivation pipeline

`derive_all_dns_names(host, site)` in `derivations/dns_names.py` runs five
passes in order, each appending to `host.dns_names`. Order matters: Pass 4
scans all names from Passes 1–3.

### Pass 1 — Hostname

Adds the base hostname names, carrying **all** interface IPs (round-robin):

| Name | FQDN | IPs |
|------|------|-----|
| `{hostname}.{domain}` | yes | all IPv4 + all IPv6 |
| `{hostname}` | no | all IPv4 + all IPv6 |

### Pass 2 — Interface

For each interface with a non-`None` name, adds per-interface names carrying
only **that interface's** IPs:

| Name | FQDN | IPs |
|------|------|-----|
| `{iface}.{hostname}.{domain}` | yes | interface IPv4 + IPv6 |
| `{iface}.{hostname}` | no | interface IPv4 + IPv6 |

Interfaces with `name=None` (the default/only interface) produce no Pass 2 names.

### Pass 3 — Subdomain

Scans existing FQDNs. For each one whose IPv4 maps to a VLAN subdomain
(via `ip_to_subdomain`), inserts the subdomain label:

| Original | Generated |
|----------|-----------|
| `{x}.{domain}` | `{x}.{subdomain}.{domain}` |

The subdomain is derived from the IPv4's third octet via `site.network_subdomains`.
For example, third octet 10 maps to subdomain `int` on the `welland` site.

### Pass 4 — IPv4/IPv6 prefix

Scans all FQDNs from Passes 1–3. For each name with IPv4 addresses,
generates `ipv4.{name}` carrying only IPv4s. For each with IPv6,
generates `ipv6.{name}` carrying only IPv6s:

| Original | Generated |
|----------|-----------|
| `server.welland.mithis.com` (has IPv4 + IPv6) | `ipv4.server.welland.mithis.com` (IPv4 only) |
| | `ipv6.server.welland.mithis.com` (IPv6 only) |

These `ipv4.*` / `ipv6.*` names are always the most-specific names (most
labels), which is critical for reverse DNS — see [Reverse DNS](#reverse-dns-ptr-record).

### Pass 5 — Alt names

Reads `host.alt_names` (from the spreadsheet's "Alt Names" column, comma or
newline separated). Each becomes a FQDN carrying all interface IPs, matching
Pass 1 treatment.


## Name expansion example

A single-interface host `desktop` on IP `10.1.10.100` (VLAN `int`, dual-stack)
produces these `dns_names` entries:

| Pass | Name | IPs |
|------|------|-----|
| 1 | `desktop.welland.mithis.com` | 10.1.10.100, 2404:e80:a137:110::100 |
| 1 | `desktop` | 10.1.10.100, 2404:e80:a137:110::100 |
| 3 | `desktop.int.welland.mithis.com` | 10.1.10.100, 2404:e80:a137:110::100 |
| 4 | `ipv4.desktop.welland.mithis.com` | 10.1.10.100 |
| 4 | `ipv6.desktop.welland.mithis.com` | 2404:e80:a137:110::100 |
| 4 | `ipv4.desktop.int.welland.mithis.com` | 10.1.10.100 |
| 4 | `ipv6.desktop.int.welland.mithis.com` | 2404:e80:a137:110::100 |

No Pass 2 names because the interface has no name (`name=None`).


## Forward DNS (host-record)

`host_record_config()` in `generators/dnsmasq_common.py` converts `host.dns_names`
into dnsmasq `host-record` lines.

### Filtering

Each `DNSName` is subject to three filters:

1. **Short names excluded** — only the bare hostname short name (`desktop`) is
   kept; interface short names (`eth0.server`) are dropped
2. **Wildcards excluded** — dnsmasq doesn't support wildcard `host-record` lines
3. **Out-of-zone excluded** — FQDNs not ending with `.{domain}` are dropped

### One IPv4, one IPv6 per line

dnsmasq's `host-record` accepts at most one IPv4 and one IPv6 address per line.
For a hostname with N IPv4s and M IPv6s (multi-interface hosts), `max(N, M)`
lines are emitted, pairing addresses positionally:

```
host-record=server.welland.mithis.com,10.1.10.1,2404:e80:a137:110::1
host-record=server.welland.mithis.com,10.1.10.2,2404:e80:a137:110::2
```

### Specificity sort

After generating all lines, they are sorted by descending dot count of the
name portion:

```python
output.sort(key=lambda line: -line.split("=", 1)[1].split(",", 1)[0].count("."))
```

This is critical because **dnsmasq auto-generates PTR records from `host-record`
lines** — the first `host-record` containing each IP determines that IP's
auto-PTR name. By placing the most-specific names first (most dots), the
auto-PTR points to `ipv4.desktop.int.welland.mithis.com` rather than
`desktop.welland.mithis.com`.

Example ordering for `desktop` (single interface, dual-stack, on `int` VLAN):

```
host-record=ipv4.desktop.int.welland.mithis.com,10.1.10.100      ← 5 dots (most specific)
host-record=ipv6.desktop.int.welland.mithis.com,2404:e80:a137:…  ← 5 dots
host-record=desktop.int.welland.mithis.com,10.1.10.100,2404:…    ← 4 dots
host-record=ipv4.desktop.welland.mithis.com,10.1.10.100           ← 4 dots
host-record=ipv6.desktop.welland.mithis.com,2404:e80:a137:…       ← 4 dots
host-record=desktop.welland.mithis.com,10.1.10.100,2404:…         ← 3 dots
host-record=desktop,10.1.10.100,2404:…                            ← 0 dots
```


## Reverse DNS (ptr-record)

Explicit `ptr-record` entries are generated by `host_ptr_config()`. These
supplement dnsmasq's auto-PTR mechanism (which generates implicit PTR records
from `host-record` ordering, as described above).

### Most-specific FQDN selection

`_most_specific_fqdn(host, ip, domain)` selects the PTR name for each IP by
finding the FQDN with the most labels (dots) that:

- Is within the authoritative zone (ends with `.{domain}`)
- Contains the target IP in its address list
- Is not an alt name

For dual-stack hosts this means IPv4 and IPv6 PTRs get different names:

| IP | PTR name |
|----|----------|
| `10.1.10.100` | `ipv4.desktop.int.welland.mithis.com` |
| `2404:e80:a137:110::100` | `ipv6.desktop.int.welland.mithis.com` |

### PTR record format

IPv4 PTRs use the slash-delimited format:
```
ptr-record=/ipv4.desktop.int.welland.mithis.com/10.1.10.100
```

IPv6 PTRs use the nibble `.ip6.arpa` format:
```
ptr-record=0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.1.0.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa,ipv6.desktop.int.welland.mithis.com
```

### PTR records use original IPs

PTR records always use the original (non-transformed) IP addresses, even in
external DNS. The `in-addr.arpa` name is derived from the actual RFC 1918
address, and IPv6 addresses are already globally routable. Only `host-record`
lines undergo the IPv4 transform.


## Split-horizon DNS

### Internal (dnsmasq.py)

Uses `identity_ipv4` — addresses are emitted as-is. Includes all record types:

1. **DHCP** (`dhcp-host`) — MAC binding with IPv4, bracketed IPv6, and DHCP name
2. **Forward DNS** (`host-record`) — all DNS names with original IPs
3. **Reverse DNS** (`ptr-record`) — IPv4 and IPv6 PTRs
4. **CAA** (`dns-rr` type 257) — Let's Encrypt issuance authorization
5. **SSHFP** (`dns-rr` type 44) — SSH fingerprints

### External (dnsmasq_external.py)

Uses `ipv4_transform = lambda ip: public_ip if is_rfc1918(ip) else ip`.
No DHCP section (external DNS doesn't do DHCP). Otherwise the same sections
as internal.

Key external behaviours:

- **RFC 1918 → public IP in host-record**: All `10.x.x.x` addresses become
  `203.0.113.1` (or whatever the site's `public_ipv4` is)
- **IPv4 deduplication**: After the transform, multiple RFC 1918 addresses
  collapse to the same public IP. A multi-interface hostname that had two
  `host-record` lines (one per IPv4/IPv6 pair) internally may produce fewer
  lines externally — the duplicated public IPv4 is emitted only once, while
  each IPv6 still gets its own line
- **PTR records unchanged**: PTR records use original IPs (RFC 1918 for IPv4)
- **SSHFP PTR uses public IP**: The PTR-based SSHFP records use the
  transformed (public) IP for the `in-addr.arpa` name

### When external is disabled

`generate_dnsmasq_external()` returns an empty dict if no `public_ipv4` is
configured. Monarto runs internal only.


## Other record types

### DHCP bindings (internal only)

```
dhcp-host=aa:bb:cc:dd:ee:ff,10.1.10.100,[2404:e80:a137:110::100],desktop
```

For hosts with multiple NICs sharing the same IPv4 (e.g. wired + wireless),
MACs are comma-joined on a single line. The DHCP name is computed via
`common_suffix()` of all interface DHCP names.

### CAA records

```
dns-rr=desktop.welland.mithis.com,257,000569737375656C657473656E63727970742E6F7267
```

Every host gets a CAA record authorizing Let's Encrypt (`0 issue "letsencrypt.org"`).
Emitted for the primary FQDN only.

### SSHFP records

```
dns-rr=server.welland.mithis.com,44,1:2:abc123
dns-rr=eth0.server.welland.mithis.com,44,1:2:abc123
dns-rr=1.10.1.10.in-addr.arpa,44,1:2:abc123
```

SSHFP records (type 44) are emitted for:
1. The hostname FQDN
2. Each named interface FQDN
3. Each interface's IPv4 PTR name (using the IPv4 transform)

Only populated when the host has `sshfp_records` derived from SSH host keys
(`ssh-keyscan` results cached in `.cache/ssh_host_keys.json`).


## Post-generation FCrDNS validation

`validate_dnsmasq_output()` in `generators/dnsmasq_common.py` runs after each
generator and checks that every `ptr-record` forward name has a matching
`host-record` name somewhere in the generated output.

This catches bugs where the PTR derivation pipeline produces a name that the
forward derivation pipeline doesn't. Matching is cross-file: a PTR in
`alpha.conf` can reference a `host-record` in `bravo.conf`.

Failures produce `ERROR`-severity violations with code `ptr_without_forward`,
which block writing output (unless `--force` is used) and cause a non-zero
exit code.


## Concrete examples

### Example 1: `desktop` — single interface, on `int` VLAN

**Spreadsheet input:**

| Machine | MAC | IP | Interface |
|---------|-----|-----|-----------|
| desktop | aa:bb:cc:dd:ee:ff | 10.1.10.100 | *(empty)* |

**Generated internal config (`desktop.conf`):**

```
# desktop — DHCP
dhcp-host=aa:bb:cc:dd:ee:ff,10.1.10.100,[2404:e80:a137:110::100],desktop

host-record=ipv4.desktop.int.welland.mithis.com,10.1.10.100
host-record=ipv6.desktop.int.welland.mithis.com,2404:e80:a137:110::100
host-record=desktop.int.welland.mithis.com,10.1.10.100,2404:e80:a137:110::100
host-record=ipv4.desktop.welland.mithis.com,10.1.10.100
host-record=ipv6.desktop.welland.mithis.com,2404:e80:a137:110::100
host-record=desktop.welland.mithis.com,10.1.10.100,2404:e80:a137:110::100
host-record=desktop,10.1.10.100,2404:e80:a137:110::100

ptr-record=/ipv4.desktop.int.welland.mithis.com/10.1.10.100
ptr-record=0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.1.0.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa,ipv6.desktop.int.welland.mithis.com

dns-rr=desktop.welland.mithis.com,257,000569737375656C657473656E63727970742E6F7267
```

**What each section does:**

- `dhcp-host` — binds MAC to IPv4+IPv6, name `desktop` for DHCP lease
- `host-record` lines sorted most-specific first (5 dots → 4 → 3 → 0) —
  dnsmasq's auto-PTR picks `ipv4.desktop.int.welland.mithis.com` for
  `10.1.10.100`'s reverse lookup
- `ptr-record` — explicit reverse DNS entries using the most-specific names
- `dns-rr` type 257 — CAA record for Let's Encrypt

### Example 2: `server` — multi-interface, on `int` VLAN

**Spreadsheet input:**

| Machine | MAC | IP | Interface |
|---------|-----|-----|-----------|
| server | aa:bb:cc:dd:ee:01 | 10.1.10.1 | *(empty)* |
| server | aa:bb:cc:dd:ee:02 | 10.1.10.2 | eth0 |

Two rows with the same machine name produce one `Host` with two interfaces.
The default (unnamed) interface gets `10.1.10.1`; the named `eth0` interface
gets `10.1.10.2`.

**Generated internal config (`server.conf`):**

```
# server — DHCP
dhcp-host=aa:bb:cc:dd:ee:01,10.1.10.1,[2404:e80:a137:110::1],server
dhcp-host=aa:bb:cc:dd:ee:02,10.1.10.2,[2404:e80:a137:110::2],eth0-server

host-record=ipv4.eth0.server.int.welland.mithis.com,10.1.10.2
host-record=ipv6.eth0.server.int.welland.mithis.com,2404:e80:a137:110::2
host-record=eth0.server.int.welland.mithis.com,10.1.10.2,2404:e80:a137:110::2
host-record=ipv4.eth0.server.welland.mithis.com,10.1.10.2
host-record=ipv6.eth0.server.welland.mithis.com,2404:e80:a137:110::2
host-record=ipv4.server.int.welland.mithis.com,10.1.10.1
host-record=ipv4.server.int.welland.mithis.com,10.1.10.2
host-record=ipv6.server.int.welland.mithis.com,2404:e80:a137:110::1
host-record=ipv6.server.int.welland.mithis.com,2404:e80:a137:110::2
host-record=eth0.server.welland.mithis.com,10.1.10.2,2404:e80:a137:110::2
host-record=server.int.welland.mithis.com,10.1.10.1,2404:e80:a137:110::1
host-record=server.int.welland.mithis.com,10.1.10.2,2404:e80:a137:110::2
host-record=ipv4.server.welland.mithis.com,10.1.10.1
host-record=ipv4.server.welland.mithis.com,10.1.10.2
host-record=ipv6.server.welland.mithis.com,2404:e80:a137:110::1
host-record=ipv6.server.welland.mithis.com,2404:e80:a137:110::2
host-record=server.welland.mithis.com,10.1.10.1,2404:e80:a137:110::1
host-record=server.welland.mithis.com,10.1.10.2,2404:e80:a137:110::2
host-record=server,10.1.10.1,2404:e80:a137:110::1
host-record=server,10.1.10.2,2404:e80:a137:110::2

ptr-record=/ipv4.server.int.welland.mithis.com/10.1.10.1
ptr-record=1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.1.0.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa,ipv6.server.int.welland.mithis.com
ptr-record=/ipv4.eth0.server.int.welland.mithis.com/10.1.10.2
ptr-record=2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.1.0.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa,ipv6.eth0.server.int.welland.mithis.com

dns-rr=server.welland.mithis.com,257,000569737375656C657473656E63727970742E6F7267
```

**Key multi-interface behaviours:**

- **Hostname names carry all IPs** — `server.welland.mithis.com` has two
  `host-record` lines, one per (IPv4, IPv6) pair. This gives round-robin DNS
  for the bare hostname.
- **Interface names carry only their IPs** — `eth0.server.welland.mithis.com`
  has only `10.1.10.2` and its IPv6. The default interface's IP (`10.1.10.1`)
  resolves only via the hostname name (no interface-specific name because
  `name=None`).
- **Each IP gets its own PTR** — `10.1.10.1` → `ipv4.server.int…` (hostname-based,
  most specific); `10.1.10.2` → `ipv4.eth0.server.int…` (interface-based,
  even more specific).
- **Two DHCP lines** — one per interface, each binding a different MAC to a
  different IP. The named interface gets `eth0-server` as its DHCP name.

### External variant (server, multi-interface)

```
host-record=ipv4.eth0.server.int.welland.mithis.com,203.0.113.1
host-record=ipv6.eth0.server.int.welland.mithis.com,2404:e80:a137:110::2
host-record=eth0.server.int.welland.mithis.com,203.0.113.1,2404:e80:a137:110::2
...
host-record=server.welland.mithis.com,203.0.113.1,2404:e80:a137:110::1
host-record=server.welland.mithis.com,2404:e80:a137:110::2
```

Note how `server.welland.mithis.com` produces two lines: the first carries
the public IPv4 (`203.0.113.1`) paired with the first IPv6, the second carries
only the second IPv6 (the public IPv4 is not repeated because both original
RFC 1918 addresses mapped to the same public IP, and deduplication removed the
duplicate).


## Source files

| File | Role |
|------|------|
| `derivations/dns_names.py` | Five-pass DNS name derivation |
| `generators/dnsmasq_common.py` | Shared host-record, ptr-record, CAA, SSHFP generation + FCrDNS validation |
| `generators/dnsmasq.py` | Internal generator (DHCP + shared sections) |
| `generators/dnsmasq_external.py` | External generator (RFC 1918 → public IP transform) |
| `models/host.py` | `DNSName`, `Host`, `NetworkInterface`, `NetworkInventory` |
| `derivations/host_builder.py` | `build_hosts()`, `build_inventory()` |
| `derivations/vlan.py` | `ip_to_subdomain()` — third-octet → subdomain mapping |
| `derivations/ipv6.py` | IPv4→IPv6 address generation |
