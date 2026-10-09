"""Issue #75: stop leases of KNOWN (dhcp-host-bound) devices adding names,
keep names for DYNAMIC devices.  P = dhcp-host carries the host base name
+ a bare host-record; Q = dhcp-host carries no name + dhcp-ignore-names
for tag:known.  Checks the spec names, the hyphenated extras, the
duplicate case, a dotted BMC host, and an unbound dynamic device."""
import itertools, pathlib, shlex, subprocess

HERE = pathlib.Path(__file__).parent.resolve()
DOM = 'iot.welland.mithis.com'
P6 = '2404:e80:a137:190::'
# (iface, mac, v4, v6) for reterm2; plus au-plug-1 and bmc.big-storage
RT = [('eth0', '02:00:00:00:01:76', '10.1.90.176', P6 + '176'),
      ('wlan0', '02:00:00:00:01:77', '10.1.90.177', P6 + '177')]
AU = ('02:00:00:00:00:01', '10.1.91.1', '2404:e80:a137:191::1')
BMC = ('02:00:00:00:00:99', '10.1.90.99', P6 + '99')
DYN = ('02:00:00:00:00:42', '10.1.90.42')
port = itertools.count(55701)

def static_records():
    r = []
    for i, _, v4, v6 in RT:
        r += [f'{i}.reterm2.{DOM},{v4},{v6}', f'ipv4.{i}.reterm2.{DOM},{v4}', f'ipv6.{i}.reterm2.{DOM},{v6}']
    for _, _, v4, v6 in RT:
        r += [f'reterm2.{DOM},{v4},{v6}', f'ipv4.reterm2.{DOM},{v4}', f'ipv6.reterm2.{DOM},{v6}']
    r += [f'au-plug-1.{DOM},{AU[1]},{AU[2]}', f'ipv4.au-plug-1.{DOM},{AU[1]}', f'ipv6.au-plug-1.{DOM},{AU[2]}']
    r += [f'bmc.big-storage.{DOM},{BMC[1]},{BMC[2]}']
    return r

def run(label, mode):
    p = next(port)
    lf = HERE / f'known-{p}.leases'
    # Leases as the devices request them: reterm2's NICs both call themselves
    # 'reterm2' (v4 + v6), the plug 'au-plug-1', the BMC 'bmc-big-storage',
    # and an unbound phone 'pixel-9a'.
    lf.write_text(
        ''.join(f'9999999999 {m} {v4} reterm2 01:{m}\n' for _, m, v4, _ in RT)
        + f'9999999999 {AU[0]} {AU[1]} au-plug-1 01:{AU[0]}\n'
        + f'9999999999 {BMC[0]} {BMC[1]} bmc-big-storage 01:{BMC[0]}\n'
        + f'9999999999 {DYN[0]} {DYN[1]} pixel-9a 01:{DYN[0]}\n'
        + 'duid 00:01:00:01:00:00:00:00:02:00:00:00:00:01\n'
        + ''.join(f'9999999999 {n} {v6} reterm2 00:03:00:01:{m}\n' for n, (_, m, _, v6) in enumerate(RT, 1)))
    args = ['/usr/sbin/dnsmasq', '--no-daemon', '--conf-file=/dev/null', '--pid-file',
            '--user=root', f'--port={p}', '--listen-address=127.0.0.1', '--bind-interfaces',
            '--no-resolv', '--no-hosts', '--expand-hosts', '--cache-size=0',
            '--log-facility=-', f'--dhcp-leasefile={lf}',
            '--dhcp-range=10.1.90.1,10.1.91.254,255.255.254.0,1h',
            f'--dhcp-range={P6}1,{P6}fffe,static',
            f'--dhcp-alternate-port={p+1000},{p+2000}',
            f'--domain={DOM},10.1.90.0/23', f'--domain={DOM},{P6}/64',
            f'--local=/{DOM}/', f'--auth-server={DOM}',
            f'--auth-zone={DOM},10.1.90.0/23,{P6}/64,2404:e80:a137:191::/64']
    binds = [(m, v4, v6, 'reterm2', f'{i}-reterm2') for i, m, v4, v6 in RT]
    binds += [(AU[0], AU[1], AU[2], 'au-plug-1', 'au-plug-1.iot'),
              (BMC[0], BMC[1], BMC[2], 'bmc-big-storage', 'bmc-big-storage')]
    for m, v4, v6, base, today in binds:
        name = {'today': f',{today}', 'P': f',{base}', 'Q': ''}[mode]
        args.append(f'--dhcp-host={m},{v4},[{v6}]{name}')
    args += [f'--host-record={r}' for r in static_records()]
    if mode == 'P':
        args += [f'--host-record=reterm2,{v4},{v6}' for _, _, v4, v6 in RT]
        args += [f'--host-record=au-plug-1,{AU[1]},{AU[2]}', f'--host-record=bmc-big-storage,{BMC[1]},{BMC[2]}']
    if mode == 'Q':
        args.append('--dhcp-ignore-names=tag:known')
    names = ([f'{pre}{i}.reterm2.{DOM}' for i in ('eth0', 'wlan0') for pre in ('', 'ipv4.', 'ipv6.')]
             + [f'{pre}reterm2.{DOM}' for pre in ('', 'ipv4.', 'ipv6.')]
             + [f'eth0-reterm2.{DOM}', f'au-plug-1.{DOM}', f'bmc.big-storage.{DOM}',
                f'bmc-big-storage.{DOM}', f'pixel-9a.{DOM}', 'pixel-9a'])
    digs = ''.join(f'echo "@@{n} {rr}"; dig +short -p {p} @127.0.0.1 {n} {rr}; '
                   for n in names for rr in ('A', 'AAAA'))
    digs += f'echo "@@PTR-dyn x"; dig +short -p {p} @127.0.0.1 -x {DYN[1]}; '
    r = subprocess.run(['sudo', 'unshare', '-n', 'sh', '-c',
                        'ip link set lo up; ip addr add 10.1.90.1/23 dev lo; '
                        f'ip addr add {P6}1/64 dev lo nodad; '
                        f'timeout 8 {shlex.join(args)} & T=$!; sleep 0.8; {digs} kill $T; wait'],
                       capture_output=True, text=True)
    lf.unlink()
    res = {}
    for c in r.stdout.split('@@')[1:]:
        n, rr, *ans = c.split()
        res[(n, rr)] = ans
    if not res:
        print(f'{label}: dnsmasq failed: {(r.stdout + r.stderr)[-400:]}'); return
    print(f'--- {label}')
    def show(a):
        if ';;' in a: raise SystemExit(f'{label}: query failed: {a}')
        return '-' if not a else ('DUP' if len(a) != len(set(a)) else str(len(a)))
    for n in names:
        print(f'    {n:<44} A={show(res[(n, "A")]):<4} AAAA={show(res[(n, "AAAA")])}')
    print(f'    PTR of dynamic {DYN[1]:<27} {res[("PTR-dyn", "x")]}')

run('today (hyphen / .iot dhcp-host names)', 'today')
run('P: base name + bare host-record', 'P')
run('Q: no dhcp-host name + dhcp-ignore-names=tag:known', 'Q')
