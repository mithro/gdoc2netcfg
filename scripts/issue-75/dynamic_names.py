"""Issue #75: what DNS does a DYNAMIC lease (no dhcp-host binding) get today?
For each such lease on roam/iot: bare + FQDN A/AAAA at the leaf, the same via
the recursor, and the PTR of its IPv4."""
import glob, re, subprocess
def dig(server, *q):
    return subprocess.run(['dig', '+short', '+time=2', f'@{server}', *q], capture_output=True, text=True).stdout.split()
for leaf, gw in (('roam', '10.1.20.1'), ('iot', '10.1.90.1')):
    dom = f'{leaf}.welland.mithis.com'
    gen = ''.join(open(f).read() for f in glob.glob(f'/etc/dnsmasq.d/{leaf}/generated/*.conf'))
    bound = {l.split(',')[0].lower() for l in re.findall(r'^dhcp-host=(.*)$', gen, re.M)}
    shown = 0
    for line in open(f'/var/lib/misc/dnsmasq.{leaf}.leases'):
        p = line.split()
        if len(p) < 5 or ':' not in p[1] or p[1].lower() in bound or p[3] == '*':
            continue
        name, ip = p[3], p[2]
        print(f'{leaf} dynamic {name} {ip}: '
              f'bare A={dig(gw, name, "A")} FQDN A={dig(gw, f"{name}.{dom}", "A")} '
              f'FQDN AAAA={dig(gw, f"{name}.{dom}", "AAAA")} via-recursor A={dig("10.1.0.1", f"{name}.{dom}", "A")} '
              f'PTR={dig(gw, "-x", ip)}')
        shown += 1
        if shown == 3:
            break
