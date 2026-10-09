"""Issue #75: check a host's live leaf answers against the naming spec:
{,ipv4.,ipv6.}{,<iface>.}<host>.<net>.<domain> -- interface names carry
that interface's addresses, host names the union; ipv4./ipv6. one family."""
import re, subprocess, sys, glob

def dig(gw, q, rr):
    return sorted(subprocess.run(['dig', '+short', '+time=2', f'@{gw}', q, rr],
                                 capture_output=True, text=True).stdout.split())

def check(leaf, gw, host, ifaces):
    dom = f'{leaf}.welland.mithis.com'
    # Expected addresses come from the dhcp-host bindings (the per-interface truth).
    conf = open(f'/etc/dnsmasq.d/{leaf}/generated/{host}.conf').read()
    want = {}
    for b in re.findall(r'^dhcp-host=(.*)$', conf, re.M):
        f = b.split(',')
        v4 = [x for x in f if re.fullmatch(r'[\d.]+', x)]
        v6 = [x.strip('[]') for x in f if x.startswith('[')]
        name = f[-1].split('.')[0]
        iface = next((i for i in ifaces if name.startswith(i + '-')), None)
        want[iface] = (v4, v6)
    all4 = sorted(a for v4, _ in want.values() for a in v4)
    all6 = sorted(a for _, v6 in want.values() for a in v6)
    rows = []
    for iface in [*ifaces, None]:
        v4, v6 = (want[iface] if iface else (all4, all6))
        base = f'{iface}.{host}' if iface else host
        for pre, e4, e6 in (('', v4, v6), ('ipv4.', v4, []), ('ipv6.', [], v6)):
            n = f'{pre}{base}.{dom}'
            g4, g6 = dig(gw, n, 'A'), dig(gw, n, 'AAAA')
            ok = g4 == sorted(e4) and g6 == sorted(e6)
            rows.append((('OK  ' if ok else 'BAD ') + n, g4, g6, sorted(e4), sorted(e6)))
    for iface in ifaces:  # hyphenated DHCP names: NOT in the spec
        n = f'{iface}-{host}.{dom}'
        rows.append(('xtra ' + n, dig(gw, n, 'A'), dig(gw, n, 'AAAA'), '-', '-'))
    print(f'== {host} on {leaf}')
    for name, g4, g6, e4, e6 in rows:
        extra = '' if name.startswith(('OK', 'xtra')) else f'   want A={e4} AAAA={e6}'
        print(f'  {name:<54} A={g4} AAAA={g6}{extra}')

check(*sys.argv[1:4], sys.argv[4].split(','))
