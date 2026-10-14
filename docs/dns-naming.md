# DNS Naming and Reverse DNS

How gdoc2netcfg derives DNS names from spreadsheet data, which server
ends up serving each name, and what is checked before the output is
written.

## Overview

Each host in the spreadsheet gets a set of DNS names derived from its
hostname, interface names, the networks its addresses are on, and its
address families. `derive_all_dns_names()` produces them in five passes;
every name carries a **scope** and a **kind**, and the generators pick
names by those two fields:

| Scope | Shape | Served by |
|-------|-------|-----------|
| `net` | `…{net}.{domain}` (`desktop.int.welland.mithis.com`) | the net's dnsmasq leaf (`dnsmasq_leaf`); wg and transit nets by the central auth (`pdns_internal`) |
| `site` | `…{domain}` with no net label (`desktop.welland.mithis.com`) | the central auth's site zone (`pdns_internal`) |
| `short` | unqualified (`desktop`) | the leaf, for the bare hostname only |

| Kind | Meaning |
|------|---------|
| `native` | carries addresses (A/AAAA) |
| `cname` | a site-scope alias pointing at a net native (a *projection*) |

The public view (`pdns_external`) ignores scope and kind and publishes
every in-domain name as a flat set of address records.

The design goals:

- **Every interface has its own records**: `eth0.reterm2`, plus
  `ipv4.`/`ipv6.` forms of every name.
- **The hostname resolves to all of the host's addresses**, on a net
  (`reterm2.iot.…`) and site-wide (`reterm2.…`).
- **Every IP reverses to its most-specific name**:
  `ipv4.eth0.reterm2.iot.welland.mithis.com`, not `reterm2.welland.mithis.com`.
- **Forward-confirmed reverse DNS (FCrDNS)**: every PTR name has a
  matching forward record.
- **Split horizon**: internally RFC 1918 addresses; publicly the site's
  IPv4.

The authoritative description of the grammar is the welland repo's
`net/drafts/dns-redesign-design.md` (§3).


## Where a query goes

Clients ask the site's pdns-recursor (`10.X.0.1`). Its `forward-zones.yml`
(`recursor_forward`) sends:

- each leaf net's zone, and that net's reverse slices, to the net's
  gateway address, where that net's dnsmasq leaf answers;
- the site zone, the wg and transit zones and the central reverses to
  pdns@internal on `127.0.0.1:5300`.

The site zone delegates every net zone (`NS` + glue, deliberately no
`DS`: dnsmasq cannot sign). A site-scope alias such as
`eth0.reterm2.welland.mithis.com` is a CNAME in the site zone; the
recursor follows it into the iot leaf.

A hostname with a net suffix (`au-plug-1.iot`, `openmesh-96-00.wifi`)
puts every name of the host that ends in `.{suffix}.{domain}` under that
net's zone cut, whether or not the host has an interface there, because
the recursor forwards the whole cut to the leaf. See [Zone-cut
names](#zone-cut-names).


## Name derivation pipeline

`derive_all_dns_names(host, site)` in `derivations/dns_names.py` runs
five passes in order, each appending to `host.dns_names`. Pass 4 scans
the names from Passes 1–3, so order matters.

`ip_to_net()` (`derivations/vlan.py`) maps an IPv4 address to its net:
the third octet for site addresses (`10.1.10.x` → `int`), the second
octet for global VLANs (`10.41.x.x` → `sm`), a (second, third) pair for
transit VLANs, and `wg` for the tunnels.

Three kinds of interface are special throughout:

- **Parked** (site addresses in `10.X.253/254`): no records from
  Passes 1–4, and left out of the default aggregate.
- **CGNAT** (tailscale, `100.64/10`): left out of site aggregates and of
  the public view; reachable by interface name.
- **No net home** (public WAN, tailscale) or a net delegated to another
  server (`fpgas` → tweed): the interface keeps a site-scope native
  record, since there is no net zone of ours to project it into.

A host with an interface on a delegated net whose hostname carries
that net's suffix (`pi4.fpgas`) produces no names in Passes 1–3: it
lives entirely in the delegated zone.

Two paths bypass these rules. An *Aggregate* override selects
interfaces by name, parked ones included. Pass 5 applies none of them:
an alt name carries every interface's addresses.

### Pass 1 — Site aggregate

| Name | Scope | Addresses |
|------|-------|-----------|
| `{hostname}.{domain}` | `site` (or `net`, if the hostname has a net suffix **and** an interface on that net: `au-plug-1.iot`) | every aggregate interface, IPv4 + IPv6 |
| `{hostname}` | `short` | the same |

The aggregate is every interface that is neither parked nor CGNAT. The
sheet's *Aggregate* column overrides it with a list of interface names.

### Pass 2 — Interfaces

For each named, non-parked interface on net `N`:

| Name | Scope / kind |
|------|--------------|
| `{iface}.{hostname}.{domain}` | `site` CNAME → the net form below |
| `{iface}.{hostname}.{N}.{domain}` | `net` native, that interface's addresses |
| `{iface}.{hostname}` | `short` |

When the hostname already ends in `.{N}` (`au-plug-1.iot` on iot), the
first form *is* the net name, so it is emitted once as a `net` native
with no projection. An interface with no net home gets
`{iface}.{hostname}.{domain}` as a `site` native.

Interfaces with no name (the sheet's Interface cell is empty) produce no
Pass 2 names.

### Pass 3 — Per-net host names

The host's non-parked interfaces are grouped by net. For each net `N`:

| Name | Scope / kind | Addresses |
|------|--------------|-----------|
| `{hostname}.{N}.{domain}` | `net` native | only the host's addresses **on N** |
| `{N}.{hostname}.{domain}` | `site` CNAME → the net form | |

The net the hostname is already suffixed with is skipped (it would
produce `…iot.iot…`), as are delegated nets.

### Pass 4 — IPv4/IPv6 prefix

For every FQDN from Passes 1–3:

- a **native** with IPv4 gets `ipv4.{name}` carrying only the IPv4s, and
  with IPv6 gets `ipv6.{name}` carrying only the IPv6s (same scope);
- a **CNAME** gets `ipv4.{alias}` → `ipv4.{target}` and `ipv6.{alias}` →
  `ipv6.{target}`, only for the families the interface has.

For a named interface, the `ipv4.*`/`ipv6.*` forms of its net name have
the most labels of any name carrying that address, which is what makes
them the reverse-DNS targets. An unnamed interface's target is the
prefix form of the per-net host name (`ipv4.au-plug-1.iot.…`).

### Pass 5 — Alt names

Each entry in the sheet's *Alt Names* column (comma or newline
separated) becomes a `site` native carrying all of the host's addresses.


## Name expansion example

`desktop` has two NICs on `int`:

| Machine | MAC | IP | Interface |
|---------|-----|-----|-----------|
| desktop | 7c:c2:55:55:c1:4e | 10.1.11.124 | eno0 |
| desktop | 7c:c2:55:55:c1:4f | 10.1.11.125 | eno1 |

Its `dns_names` (IPv6 omitted; `…` is `welland.mithis.com`):

| Pass | Name | Scope / kind | Addresses |
|------|------|--------------|-----------|
| 1 | `desktop.…` | site native | .124, .125 |
| 1 | `desktop` | short | .124, .125 |
| 2 | `eno0.desktop.…` | site CNAME → `eno0.desktop.int.…` | |
| 2 | `eno0.desktop.int.…` | net native | .124 |
| 2 | `eno0.desktop` | short | .124 |
| 2 | `eno1.desktop.…`, `eno1.desktop.int.…`, `eno1.desktop` | as for eno0 | .125 |
| 3 | `desktop.int.…` | net native | .124, .125 |
| 3 | `int.desktop.…` | site CNAME → `desktop.int.…` | |
| 4 | `ipv4.` and `ipv6.` forms of every FQDN above | as the original | one family |


## The leaf fragment (`dnsmasq_leaf`)

`generate_dnsmasq_leaf()` writes one fragment per host per leaf net the
host has an interface on, keyed `{net}/generated/{hostname}.conf`, so
the output tree mirrors `/etc/dnsmasq.d/`. wg, transit and delegated
nets have no leaf. A fragment holds only that net's view of the host, in
this order:

1. `dhcp-host` bindings for the host's interfaces on the net
2. `host-record` lines for the net's native names
3. `host-record` for the short hostname, **only if this is the host's
   only net**
4. the bare DHCP-name `host-record` (see [DHCP bindings](#dhcp-bindings))
5. `ptr-record` lines for the host's addresses on the net
6. CAA, only for a hostname with this net's suffix
7. advisory SSHFP

`/etc/dnsmasq.d/int/generated/desktop.conf`:

```
# desktop — DHCP
dhcp-host=7c:c2:55:55:c1:4e,10.1.11.124,[2404:e80:a137:111::124],desktop
dhcp-host=7c:c2:55:55:c1:4f,10.1.11.125,[2404:e80:a137:111::125],desktop

host-record=ipv4.eno0.desktop.int.welland.mithis.com,10.1.11.124
host-record=ipv6.eno0.desktop.int.welland.mithis.com,2404:e80:a137:111::124
host-record=ipv4.eno1.desktop.int.welland.mithis.com,10.1.11.125
host-record=ipv6.eno1.desktop.int.welland.mithis.com,2404:e80:a137:111::125
host-record=eno0.desktop.int.welland.mithis.com,10.1.11.124,2404:e80:a137:111::124
host-record=eno1.desktop.int.welland.mithis.com,10.1.11.125,2404:e80:a137:111::125
host-record=ipv4.desktop.int.welland.mithis.com,10.1.11.124
host-record=ipv4.desktop.int.welland.mithis.com,10.1.11.125
host-record=ipv6.desktop.int.welland.mithis.com,2404:e80:a137:111::124
host-record=ipv6.desktop.int.welland.mithis.com,2404:e80:a137:111::125
host-record=desktop.int.welland.mithis.com,10.1.11.124,2404:e80:a137:111::124
host-record=desktop.int.welland.mithis.com,10.1.11.125,2404:e80:a137:111::125

host-record=desktop,10.1.11.124,2404:e80:a137:111::124
host-record=desktop,10.1.11.125,2404:e80:a137:111::125

ptr-record=124.11.1.10.in-addr.arpa,ipv4.eno0.desktop.int.welland.mithis.com
ptr-record=4.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.1.1.1.0.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa,ipv6.eno0.desktop.int.welland.mithis.com
ptr-record=125.11.1.10.in-addr.arpa,ipv4.eno1.desktop.int.welland.mithis.com
ptr-record=5.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.1.1.1.0.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa,ipv6.eno1.desktop.int.welland.mithis.com
```

No site-scope name (`desktop.welland.mithis.com`) and no CNAME appears
in a leaf; those are in the central zone.

### Forward records (`host-record`)

`host_record_config()` in `generators/dnsmasq_common.py` turns a list of
`DNSName`s into `host-record` lines. The leaf passes it the names with
`scope == "net"`, `net == <this net>` and `kind == "native"`.

- **Filters**: of the short names only the bare hostname is kept
  (`eno0.desktop` is dropped); wildcards and FQDNs outside `.{domain}`
  are dropped.
- **One IPv4 and one IPv6 per line**: that is all dnsmasq accepts. A
  name with N IPv4s and M IPv6s gives `max(N, M)` lines, paired by
  position.
- **Most dots first**: dnsmasq also derives an implicit PTR from the
  first `host-record` containing each address, so the lines are sorted
  by descending label count to make that agree with the explicit
  `ptr-record`.

A host on two nets gets a fragment in each, each with only that net's
addresses. `big-storage` has `10g1`/`10g2` on int and `25g1`/`25g2` on
store, so `big-storage.int.…` answers `10.1.11.154`/`.155` from the int
leaf and `big-storage.store.…` answers `10.1.7.15`/`.16` from the store
leaf. It gets no short `big-storage` record from the hostname rule
(two nets, no unambiguous home); the bare DHCP-name record below
provides one in each leaf.

### Reverse records (`ptr-record`)

`_net_ptr_config()` emits one PTR per address the host has on the net.
The target is `_most_specific_fqdn()`: the in-zone FQDN with the most
labels that carries the address, alt names excluded. For a named
interface that is the net-scoped prefix form:

| IP | PTR name |
|----|----------|
| `10.1.11.124` | `ipv4.eno0.desktop.int.welland.mithis.com` |
| `2404:e80:a137:111::124` | `ipv6.eno0.desktop.int.welland.mithis.com` |

Both families use the arpa-name form, `ptr-record=<arpa name>,<target>`.
PTRs always use the real addresses, never the public transform.

### DHCP bindings

`_net_dhcp_config()` emits one `dhcp-host` per interface (per MAC + IPv4,
with the bracketed IPv6). MACs that share one IPv4 (the pucks'
`wan` + `lan`) are comma-joined on a single line. A host whose sheet
*Type* is `static` or `DHCP:wisp` gets no bindings at all
(`dhcp_suppressed()`): its address is configured on the device or served
by another DHCP server, and a second binding for an address bound
elsewhere is a fatal dnsmasq startup error. Its DNS records are
unaffected.

Every `dhcp-host` of a host on a net carries the **same** name: the
hostname without that net's own suffix, with any other dots turned into
hyphens (`au-plug-1.iot` → `au-plug-1` in the iot leaf, `bmc.big-storage`
→ `bmc-big-storage`, both NICs of `desktop` → `desktop`,
`openmesh-96-00.wifi` → `openmesh-96-00-wifi` in the int leaf). dnsmasq
cuts a `dhcp-host` name at its first dot, so dotted names would
otherwise collapse (every BMC would become `bmc`). The leaf also gets a
bare `host-record` of that name with all of the host's addresses on the
net:

```
dhcp-host=7c:2c:67:d9:ba:24,10.1.91.1,[2404:e80:a137:191::1],au-plug-1
host-record=au-plug-1,10.1.91.1,2404:e80:a137:191::1
```

When the short-hostname record (item 3 above) is already that exact
name, it is not repeated.

Without the bare record, a known device's lease publishes its name
itself, and dnsmasq's auth path answers a zone name from both the lease
and the host-records without deduplicating: every A came back twice, and
lease-only per-interface names (`eth0-reterm2.iot.…`) appeared outside
the naming scheme (issue #75). With it, dnsmasq keeps the lease out of
DNS (the name already exists in config with that address), so a known
host's names come only from the generated records.

### Names that do not come from the sheet

A device with no sheet row gets a dynamic lease, and dnsmasq publishes
the name the device sent: `Pixel-9a` on roam resolves as `Pixel-9a`,
as `Pixel-9a.roam.welland.mithis.com` (the leaf's `domain=`), and by
reverse lookup. dnsmasq only knows the addresses it leased: `Pixel-9a`
configures IPv6 by SLAAC and takes no DHCPv6 lease, so it has an A
record and no AAAA.

The leaves do not read `/etc/hosts` (`no-hosts` in the hand-maintained
`/etc/dnsmasq.d/shared/00-base.conf`). Its `127.0.0.1 ten64` line used
to make every leaf answer a bare `ten64` with loopback. Every name a
leaf serves comes from its generated records or its leases.

### Zone-cut names

`openmesh-96-00.wifi` has interfaces on int, net, roam, guest and iot,
and none on wifi. Its hostname still puts names like
`ipv4.poe.openmesh-96-00.wifi.welland.mithis.com` under the
`wifi.welland.mithis.com` cut, which the recursor forwards to the wifi
leaf. `_zone_cut_fragment()` therefore writes a fragment into the wifi
leaf with every FQDN of the host that ends in `.wifi.{domain}`, carrying
the host's real (other-net) addresses. It has no DHCP, PTR or SSHFP
section; those belong to the nets the interfaces are on.

### CAA and SSHFP in the leaf

- **CAA** (`dns-rr=…,257,…`, `0 issue "letsencrypt.org"`): only for a
  hostname with this net's suffix (`au-plug-1.iot`), whose canonical
  name lives in the leaf's zone.
- **SSHFP** (`dns-rr=…,44,alg:type:fingerprint`): at
  `{hostname}.{net}.{domain}`, each named interface's net name, and each
  IPv4's arpa name. dnsmasq cannot sign, so these are advisory; the
  enforceable copies are at the signed site name in the central zone.
  SSHFP records are derived at runtime from the SSH host keys in
  `discovery.db`.


## The central zones (`pdns_internal`)

`generate_pdns_internal()` in `generators/pdns_zones.py` writes
bind-backend zone files for pdns@internal:

- **`{domain}.zone`**, the site zone:
  - `NS` + glue delegating every net zone (to the net's gateway on
    `ten64`, to the central auth itself for wg/transit nets, or to the
    other server for a delegated net);
  - every `site`-scope name: natives as A/AAAA, CNAME-kind names as
    `CNAME`;
  - CAA and SSHFP at `{hostname}.{domain}` for each host that has a site
    native;
  - an optional `$INCLUDE` of hand-maintained records.
- **`wg.{domain}.zone`** and one zone per transit VLAN: the `net`-scope
  natives of those nets, which have no leaf.
- **Reverse zones** for the central-served nets, plus catch-all reverses
  for addresses outside every leaf's slices.

`desktop` in the site zone:

```
desktop.welland.mithis.com. 300 IN A 10.1.11.124
desktop.welland.mithis.com. 300 IN A 10.1.11.125
desktop.welland.mithis.com. 300 IN AAAA 2404:e80:a137:111::124
desktop.welland.mithis.com. 300 IN AAAA 2404:e80:a137:111::125
eno0.desktop.welland.mithis.com. 300 IN CNAME eno0.desktop.int.welland.mithis.com.
eno1.desktop.welland.mithis.com. 300 IN CNAME eno1.desktop.int.welland.mithis.com.
int.desktop.welland.mithis.com. 300 IN CNAME desktop.int.welland.mithis.com.
ipv4.desktop.welland.mithis.com. 300 IN A 10.1.11.124
ipv4.desktop.welland.mithis.com. 300 IN A 10.1.11.125
ipv6.desktop.welland.mithis.com. 300 IN AAAA 2404:e80:a137:111::124
ipv6.desktop.welland.mithis.com. 300 IN AAAA 2404:e80:a137:111::125
ipv4.eno0.desktop.welland.mithis.com. 300 IN CNAME ipv4.eno0.desktop.int.welland.mithis.com.
ipv6.eno0.desktop.welland.mithis.com. 300 IN CNAME ipv6.eno0.desktop.int.welland.mithis.com.
…
ipv4.int.desktop.welland.mithis.com. 300 IN CNAME ipv4.desktop.int.welland.mithis.com.
ipv6.int.desktop.welland.mithis.com. 300 IN CNAME ipv6.desktop.int.welland.mithis.com.
desktop.welland.mithis.com. 300 IN CAA 0 issue "letsencrypt.org"
```

For a multi-net host the site aggregate spans the nets:
`big-storage.welland.mithis.com` carries all four addresses, with
`int.big-storage.…` and `store.big-storage.…` projecting to the two
per-net names.


## The public zone (`pdns_external`)

`generate_pdns_external()` writes one flat zone for pdns@external. It
emits nothing when the site has no `public_ipv4` (argument or
`site.public_ipv4`).

- **Every in-domain FQDN becomes address records**, site and net scope
  alike, CNAME-kind names included. There are no CNAMEs and no
  delegations: the leaves are not publicly reachable.
- **RFC 1918 IPv4 → the site's public IPv4.** IPv6 is published as-is.
  Several private addresses collapse to one public A, which is emitted
  once.
- **CGNAT addresses are never published.**
- **No reverse zones.**
- **CAA and SSHFP** only at `{hostname}.{domain}`.
- `NS` names the Rollernet secondaries; ten64 is their hidden primary.

```
desktop.welland.mithis.com. 300 IN A 87.121.95.37
desktop.welland.mithis.com. 300 IN AAAA 2404:e80:a137:111::124
desktop.welland.mithis.com. 300 IN AAAA 2404:e80:a137:111::125
eno0.desktop.welland.mithis.com. 300 IN A 87.121.95.37
eno0.desktop.welland.mithis.com. 300 IN AAAA 2404:e80:a137:111::124
eno0.desktop.int.welland.mithis.com. 300 IN A 87.121.95.37
eno0.desktop.int.welland.mithis.com. 300 IN AAAA 2404:e80:a137:111::124
```


## Post-generation validation

`validate_dnsmasq_output()` in `generators/dnsmasq_common.py` runs on the
output of the generators listed in `FCRDNS_VALIDATED_GENERATORS`
(`cli/main.py`), currently `dnsmasq_leaf`: the files a deploy installs.
Each failure is an `ERROR` violation: `generate` exits non-zero and
skips writing that generator's output, unless `--force` is given (the
exit code stays non-zero). Deploys never use `--force`.

| Code | Checks |
|------|--------|
| `ptr_without_forward` | every `ptr-record` target is also a `host-record` name somewhere in the output (matching is cross-file) |
| `dhcp_name_without_record` | every `dhcp-host` name has a bare `host-record` of that name, in the same net, containing the binding's IPv4 |
| `dhcp_name_collision` | no two host files in one net use the same `dhcp-host` name |

The first catches the PTR derivation producing a name the forward
derivation does not. The other two guard the rule in [DHCP
bindings](#dhcp-bindings): a name without its record brings back the
duplicated answers, and a shared name makes dnsmasq move the name
between leases.


## Source files

| File | Role |
|------|------|
| `derivations/dns_names.py` | Five-pass DNS name derivation (scope, kind, projections) |
| `derivations/vlan.py` | `ip_to_net()`; parked and delegated nets |
| `derivations/ipv6.py` | IPv4→IPv6 address generation |
| `derivations/host_builder.py` | `build_hosts()`, `build_inventory()` |
| `models/host.py` | `DNSName`, `Host`, `NetworkInterface`, `NetworkInventory` |
| `generators/dnsmasq_leaf.py` | Per-net leaf fragments: DHCP, net natives, PTR, zone-cut names |
| `generators/dnsmasq_common.py` | `host_record_config()`, PTR helpers, `dhcp_suppressed()`, post-generation validation |
| `generators/pdns_zones.py` | Central internal zones: site zone, wg/transit zones, reverses |
| `generators/pdns_external.py` | Public zone |
| `generators/recursor_forward.py` | The recursor's zone → server routing table |
