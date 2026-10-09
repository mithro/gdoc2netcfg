"""Issue #75 design check: can each per-net leaf be given BARE names and
let dnsmasq qualify them with the leaf's domain?  Runs the installed
dnsmasq in a private network namespace (only lo) with the iot-leaf shape:
auth-zone, a matching DHCP lease, expand-hosts (as shared/00-base.conf),
and reports A/AAAA for the FQDN, the bare name and a dotted variant."""
import itertools, pathlib, shlex, subprocess

HERE = pathlib.Path(__file__).parent.resolve()
MAC, IP, IP6 = '7c:2c:67:d7:c1:08', '10.1.91.41', '2404:e80:a137:191::41'
DOM = 'iot.welland.mithis.com'
port = itertools.count(55401)
QUERIES = [('fqdn', f'au-plug-41.{DOM}'), ('bare', 'au-plug-41'),
           ('ipv4.fqdn', f'ipv4.au-plug-41.{DOM}')]

def run(label, records=(), hosts=(), extra=(), v6_domain=False):
    p = next(port)
    lf, hf = HERE / f'expand-{p}.leases', HERE / f'expand-{p}.hosts'
    lf.write_text(f'9999999999 {MAC} {IP} au-plug-41 01:{MAC}\n')
    hf.write_text(''.join(f'{a} {n}\n' for a, n in hosts))
    args = ['/usr/sbin/dnsmasq', '--no-daemon', '--conf-file=/dev/null', '--pid-file',
            '--user=root', f'--port={p}', '--listen-address=127.0.0.1', '--bind-interfaces',
            '--no-resolv', '--no-hosts', '--expand-hosts', '--cache-size=0',
            '--log-facility=-', f'--dhcp-leasefile={lf}', f'--addn-hosts={hf}',
            '--dhcp-range=10.1.90.1,10.1.91.254,255.255.254.0,1h',
            f'--dhcp-alternate-port={p+1000},{p+2000}',
            f'--domain={DOM},10.1.90.0/23', f'--local=/{DOM}/',
            f'--auth-server={DOM}',
            f'--auth-zone={DOM},10.1.90.0/23,2404:e80:a137:190::/64,2404:e80:a137:191::/64',
            f'--dhcp-host={MAC},{IP},[{IP6}],au-plug-41']
    if v6_domain:
        args.append(f'--domain={DOM},2404:e80:a137:191::/64')
    args += [f'--host-record={r}' for r in records] + list(extra)
    digs = ''.join(f'echo "@@{tag} {rr}"; dig +short -p {p} @127.0.0.1 {name} {rr}; '
                   for tag, name in QUERIES for rr in ('A', 'AAAA'))
    # timeout bounds the test dnsmasq; it lives only in this private netns.
    inner = (f'timeout 2 {shlex.join(args)} & sleep 0.7; {digs} wait')
    r = subprocess.run(['sudo', 'unshare', '-n', 'sh', '-c',
                        'ip link set lo up; ip addr add 10.1.90.1/23 dev lo; '
                        'ip addr add 2404:e80:a137:191::1/64 dev lo nodad; ' + inner],
                       capture_output=True, text=True)
    lf.unlink(); hf.unlink()
    res = {}
    for chunk in r.stdout.split('@@')[1:]:
        head, *ans = chunk.split()
        rr = ans.pop(0)
        res[(head, rr)] = ans
    if not res:
        print(f'{label}: dnsmasq failed:\n{r.stdout[-400:]}{r.stderr[-400:]}'); return
    cells = []
    for tag, _ in QUERIES:
        for rr in ('A', 'AAAA'):
            a = res.get((tag, rr), [])
            cells.append(f'{tag} {rr}=' + ('-' if not a else ('DUP' if len(a) != len(set(a)) else str(len(a)))))
    print(f'{label:<44} ' + '  '.join(cells))

FQDN_RECS = [f'au-plug-41.{DOM},{IP},{IP6}', f'ipv4.au-plug-41.{DOM},{IP}']
run('today: FQDN host-records only', records=FQDN_RECS)
run('bare host-record only', records=[f'au-plug-41,{IP},{IP6}'])
run('hosts file, bare name only', hosts=[(IP, 'au-plug-41'), (IP6, 'au-plug-41')])
run('hosts file bare + v6 domain= line', hosts=[(IP, 'au-plug-41'), (IP6, 'au-plug-41')], v6_domain=True)
run('hosts file, dotted ipv4.au-plug-41', hosts=[(IP, 'ipv4.au-plug-41')])
run('FQDN records + bare host-record', records=FQDN_RECS + [f'au-plug-41,{IP},{IP6}'])
