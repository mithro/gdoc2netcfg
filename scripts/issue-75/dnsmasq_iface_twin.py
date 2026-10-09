"""Issue #75: a multi-interface host's dhcp-host name is hyphenated
(eth0-x) while its static names are dotted (eth0.x).  Does adding only a
BARE twin record for the dhcp-host name break the lease-published FQDN
eth0-x.<dom>?  And does a bare + FQDN twin pair keep every name, once?"""
import itertools, pathlib, shlex, subprocess

HERE = pathlib.Path(__file__).parent.resolve()
MAC, IP, IP6 = '00:13:20:fe:41:64', '10.1.90.241', '2404:e80:a137:190::241'
DOM = 'iot.welland.mithis.com'
STATIC = [f'eth0.minnow-turbot-1.{DOM},{IP},{IP6}', f'ipv4.eth0.minnow-turbot-1.{DOM},{IP}',
          f'minnow-turbot-1.{DOM},{IP},{IP6}', f'minnow-turbot-1,{IP},{IP6}']
NAMES = ['eth0-minnow-turbot-1', f'eth0-minnow-turbot-1.{DOM}', f'eth0.minnow-turbot-1.{DOM}',
         f'ipv4.eth0.minnow-turbot-1.{DOM}', f'minnow-turbot-1.{DOM}']
port = itertools.count(55601)

def run(label, extra_records=(), lease=True):
    p = next(port)
    lf = HERE / f'twin-{p}.leases'
    lf.write_text(f'9999999999 {MAC} {IP} eth0-minnow-turbot-1 01:{MAC}\n' if lease else '')
    args = ['/usr/sbin/dnsmasq', '--no-daemon', '--conf-file=/dev/null', '--pid-file',
            '--user=root', f'--port={p}', '--listen-address=127.0.0.1', '--bind-interfaces',
            '--no-resolv', '--no-hosts', '--expand-hosts', '--cache-size=0',
            '--log-facility=-', f'--dhcp-leasefile={lf}',
            '--dhcp-range=10.1.90.1,10.1.91.254,255.255.254.0,1h',
            f'--dhcp-alternate-port={p+1000},{p+2000}',
            f'--domain={DOM},10.1.90.0/23', f'--local=/{DOM}/', f'--auth-server={DOM}',
            f'--auth-zone={DOM},10.1.90.0/23,2404:e80:a137:190::/64',
            f'--dhcp-host={MAC},{IP},[{IP6}],eth0-minnow-turbot-1']
    args += [f'--host-record={r}' for r in [*STATIC, *extra_records]]
    digs = ''.join(f'echo "@@{n} {rr}"; dig +short -p {p} @127.0.0.1 {n} {rr}; '
                   for n in NAMES for rr in ('A', 'AAAA'))
    r = subprocess.run(['sudo', 'unshare', '-n', 'sh', '-c',
                        'ip link set lo up; ip addr add 10.1.90.1/23 dev lo; '
                        f'timeout 2 {shlex.join(args)} & sleep 0.7; {digs} wait'],
                       capture_output=True, text=True)
    lf.unlink()
    res = {}
    for c in r.stdout.split('@@')[1:]:
        n, rr, *ans = c.split()
        res[(n, rr)] = ans
    if not res:
        print(f'{label}: dnsmasq failed: {(r.stdout + r.stderr)[-300:]}'); return
    print(f'--- {label}')
    for n in NAMES:
        cells = []
        for rr in ('A', 'AAAA'):
            a = res[(n, rr)]
            cells.append(f'{rr}=' + ('-' if not a else 'DUP' if len(a) != len(set(a)) else 'ok'))
        print(f'    {n:<46} {"  ".join(cells)}')

run('today (static dotted names only)')
run('+ bare twin only', [f'eth0-minnow-turbot-1,{IP},{IP6}'])
run('+ bare AND FQDN twin', [f'eth0-minnow-turbot-1,{IP},{IP6}', f'eth0-minnow-turbot-1.{DOM},{IP},{IP6}'])
run('+ bare AND FQDN twin, device offline', [f'eth0-minnow-turbot-1,{IP},{IP6}', f'eth0-minnow-turbot-1.{DOM},{IP},{IP6}'], lease=False)
