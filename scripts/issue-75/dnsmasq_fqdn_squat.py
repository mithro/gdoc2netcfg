"""Issue #75: does a leaf need option A (bare host-record per dhcp-host),
option D (dhcp-fqdn in the leaf template), or both?  Each run is the
installed dnsmasq in a private netns (iot-leaf shape: auth-zone,
expand-hosts) with ONE lease: either the real device, or an unknown
device (different MAC, dynamic IP) that claims the same hostname."""
import itertools, pathlib, shlex, subprocess

HERE = pathlib.Path(__file__).parent.resolve()
MAC, IP, IP6 = '7c:2c:67:d7:c1:08', '10.1.91.41', '2404:e80:a137:191::41'
ROGUE_MAC, ROGUE_IP = '02:00:00:00:00:66', '10.1.90.200'
DOM = 'iot.welland.mithis.com'
port = itertools.count(55501)

def run(label, bare_rec=False, fqdn_opt=False, rogue=False):
    p = next(port)
    lf = HERE / f'squat-{p}.leases'
    mac, ip = (ROGUE_MAC, ROGUE_IP) if rogue else (MAC, IP)
    lf.write_text(f'9999999999 {mac} {ip} au-plug-41 01:{mac}\n')
    args = ['/usr/sbin/dnsmasq', '--no-daemon', '--conf-file=/dev/null', '--pid-file',
            '--user=root', f'--port={p}', '--listen-address=127.0.0.1', '--bind-interfaces',
            '--no-resolv', '--no-hosts', '--expand-hosts', '--cache-size=0',
            '--log-facility=-', f'--dhcp-leasefile={lf}',
            '--dhcp-range=10.1.90.1,10.1.91.254,255.255.254.0,1h',
            f'--dhcp-alternate-port={p+1000},{p+2000}',
            f'--domain={DOM},10.1.90.0/23', f'--local=/{DOM}/',
            f'--auth-server={DOM}',
            f'--auth-zone={DOM},10.1.90.0/23,2404:e80:a137:190::/64,2404:e80:a137:191::/64',
            f'--dhcp-host={MAC},{IP},[{IP6}],au-plug-41',
            f'--host-record=au-plug-41.{DOM},{IP},{IP6}']
    if bare_rec:
        args.append(f'--host-record=au-plug-41,{IP},{IP6}')
    if fqdn_opt:  # dhcp-fqdn requires a range-less default domain
        args += ['--dhcp-fqdn', f'--domain={DOM}']
    digs = (f'echo @@fqdn; dig +short -p {p} @127.0.0.1 au-plug-41.{DOM} A; '
            f'echo @@bare; dig +short -p {p} @127.0.0.1 au-plug-41 A; ')
    inner = f'timeout 2 {shlex.join(args)} & sleep 0.7; {digs} wait'
    r = subprocess.run(['sudo', 'unshare', '-n', 'sh', '-c',
                        'ip link set lo up; ip addr add 10.1.90.1/23 dev lo; ' + inner],
                       capture_output=True, text=True)
    lf.unlink()
    res = dict((c.split()[0], c.split()[1:]) for c in r.stdout.split('@@')[1:])
    if not res:
        print(f'{label}: dnsmasq failed: {(r.stdout + r.stderr)[-300:]}'); return
    warn = [l.split(': ', 1)[1] for l in (r.stdout + r.stderr).splitlines() if 'not giving name' in l]
    print(f'{label:<34} FQDN A={res["fqdn"]!s:<28} bare A={res["bare"]!s:<16} {warn[:1]}')

for who in (False, True):
    print('--- lease held by', 'an UNKNOWN device claiming au-plug-41 (10.1.90.200)' if who else 'the real device')
    run('today', rogue=who)
    run('A: bare host-record', bare_rec=True, rogue=who)
    run('D: dhcp-fqdn', fqdn_opt=True, rogue=who)
    run('A + D', bare_rec=True, fqdn_opt=True, rogue=who)
