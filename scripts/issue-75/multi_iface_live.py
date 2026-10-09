"""Issue #75: live answers for hosts with several interfaces on ONE net:
per-interface dhcp names (eth0-x/wlan0-x), one name on two IPs
(tplink-powerline), several MACs sharing one IP (printer/roku), and the
host-level aggregate name."""
import re, subprocess, glob
def dig(gw, q, rr='A'):
    return subprocess.run(['dig', '+short', '+time=2', f'@{gw}', q, rr], capture_output=True, text=True).stdout.split()
def leases(leaf):
    return {p[3]: p[2] for p in (l.split() for l in open(f'/var/lib/misc/dnsmasq.{leaf}.leases')) if len(p) > 3 and '.' in p[2]}
CASES = [('iot', '10.1.90.1', 'reterm2'), ('iot', '10.1.90.1', 'rpi5-zigbee'), ('net', '10.1.5.1', 'tplink-powerline'),
         ('roam', '10.1.20.1', 'printer'), ('roam', '10.1.20.1', 'roku'), ('int', '10.1.10.1', 'big-storage')]
for leaf, gw, host in CASES:
    dom = f'{leaf}.welland.mithis.com'
    conf = open(glob.glob(f'/etc/dnsmasq.d/{leaf}/generated/{host}.conf')[0]).read()
    binds = re.findall(r'^dhcp-host=(.*)$', conf, re.M)
    lz = leases(leaf)
    print(f'== {host} ({leaf})  aggregate {host}.{dom} A={dig(gw, f"{host}.{dom}")}')
    for b in binds:
        f = b.split(',')
        name, ip = f[-1], next(x for x in f if re.fullmatch(r'[\d.]+', x))
        label = name.split('.')[0]
        held = {n: a for n, a in lz.items() if n == label}
        print(f'   dhcp-host {name:<26} {ip:<12} lease={held or "-"}  '
              f'{label}.{dom} A={dig(gw, f"{label}.{dom}")}  bare A={dig(gw, label)}')
