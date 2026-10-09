# Issue #75 evidence: duplicate A records from the dnsmasq leaves

One-off investigation scripts, kept in history as evidence for the fix.
They were deleted again in the commit after the one that added them.
The `dnsmasq_*` and `replay_leaf` scripts run the installed
`/usr/sbin/dnsmasq` as root inside `sudo unshare -n`, a private network
namespace with only its own `lo`, so they never touch the production
leaves. The others query the live leaves or read `/etc/dnsmasq.d`.

| script | what it showed |
|---|---|
| `dnsmasq_dup_repro.py` | Duplicate needs `auth-zone` + a lease and a `host-record` with the same address; the cause is the bare lease name with no matching bare record |
| `lease_dup_scan.py` | Live: a lease name duplicates exactly when an FQDN record exists but no bare record (65 on welland iot) |
| `dnsmasq_hosts_expand.py` | Bare `host-record`s are never qualified with the domain; hosts files only qualify dot-free names, and AAAA only with a v6 `domain=` line |
| `dnsmasq_fqdn_squat.py`, `squat_gap.py` | Today any lease can add an address to a same-named static FQDN (ruled out of scope) |
| `dynamic_names.py` | Unbound (dynamic) leases get bare + FQDN names and a PTR; must stay that way |
| `multi_iface_live.py` | Several interfaces on one net: one lease name per NIC, published only while leased |
| `dnsmasq_iface_twin.py` | A bare-only record hides a lease FQDN; the bare+FQDN pair keeps it |
| `naming_spec_check.py` | Live check of the naming spec (`{,ipv4.,ipv6.}{,<iface>.}<host>.<net>.<domain>`) |
| `dnsmasq_known_names.py` | Option P (one name + bare record) meets the spec; option Q not testable with pre-loaded leases |
| `make_pq.py` | Builds P and Q versions of real leaf files for `git diff --word-diff` |
| `compare_leaf.py` | Branch output vs `/etc`: only 295 `dhcp-host` renames and 192 added bare records |
| `replay_leaf.py`, `replay_compare.py` | Real iot/roam leaf replayed: 65 duplicates become 0, no address changes, only lease-only names lost, dynamic names kept |
