"""Reproduce the duplicate-A answer in an isolated, unprivileged dnsmasq.

Each variant changes ONE thing relative to the production iot-leaf shape
(dhcp-host name 'x.iot', FQDN host-record, short 'x.iot' host-record,
cache-size=0) and counts the A answers for x.iot.welland.mithis.com.
"""
import subprocess, time, pathlib, itertools, shlex

HERE = pathlib.Path(__file__).parent
MAC, IP, IP6 = '7c:2c:67:d7:c1:08', '10.1.91.41', '2404:e80:a137:191::41'
FQDN = 'au-plug-41.iot.welland.mithis.com'
port = itertools.count(55301)
import os
SHOWLOG = bool(os.environ.get('SHOWLOG'))

def run(label, dhcp_name='au-plug-41.iot', short_rec=True, cache0=True, lease=True, auth=False, v6lease=False, short_name='au-plug-41.iot', fqdn_opt=False):
    p = next(port)
    lf = (HERE / f'repro-{p}.leases').resolve()
    lf.write_text((f'9999999999 {MAC} {IP} au-plug-41 01:{MAC}\n' if lease else '')
                 + '9999999999 02:00:00:00:00:99 10.1.90.99 leaseonly 01:02:00:00:00:00:99\n'
                 + (f'duid 00:04:10:8e:2f:f3:0a:0f:c1:6e:18:2f:b7:8a:0c:83:76:1e\n'
                    f'9999999999 1448103320 {IP6} au-plug-41 00:04:10:8e:2f:f3:0a:0f:c1:6e:18:2f:b7:8a:0c:83:76:1e\n' if v6lease else ''))
    args = ['/usr/sbin/dnsmasq', '--no-daemon', '--conf-file=/dev/null', '--pid-file', '--user=root',
            f'--port={p}', '--listen-address=127.0.0.1', '--bind-interfaces',
            '--no-resolv', '--no-hosts', '--log-queries=extra', '--log-facility=-',
            f'--dhcp-range=10.1.90.1,10.1.91.254,255.255.254.0,1h',
            f'--dhcp-alternate-port={p+1000},{p+2000}',
            f'--dhcp-leasefile={lf}', '--domain=iot.welland.mithis.com,10.1.90.0/23',
            '--local=/iot.welland.mithis.com/',
            f'--dhcp-host={MAC},{IP},{dhcp_name}',
            f'--host-record={FQDN},{IP},{IP6}']
    if short_rec: args.append(f'--host-record={short_name},{IP},{IP6}')
    if cache0: args.append('--cache-size=0')
    if fqdn_opt: args.append('--dhcp-fqdn')
    if v6lease: args.append('--dhcp-range=2404:e80:a137:191::1,2404:e80:a137:191::fffe,static')
    if auth: args += ['--auth-server=iot.welland.mithis.com',
                      '--auth-zone=iot.welland.mithis.com,10.1.90.0/23,2404:e80:a137:190::/64,2404:e80:a137:191::/64']
    # Own network namespace: only an isolated lo, so nothing reaches prod.
    inner = ('timeout 2 ' + ' '.join(shlex.quote(x) for x in args) + ' & T=$!; sleep 0.7; '
             f'echo A; dig +short -p {p} @127.0.0.1 {FQDN} A; '
             f'echo AAAA; dig +short -p {p} @127.0.0.1 {FQDN} AAAA; '
             f'echo SANITY; dig +short -p {p} @127.0.0.1 leaseonly.iot.welland.mithis.com A; echo BARE; dig +short -p {p} @127.0.0.1 au-plug-41 A; '
             # SIGUSR1 = cache dump; -P $T only matches OUR timeout's child.
             'kill -USR1 $(pgrep -P $T -x dnsmasq); sleep 0.3; wait')
    r = subprocess.run(['sudo', 'unshare', '-n', 'sh', '-c', 'ip link set lo up; ip addr add 10.1.90.1/23 dev lo; ip addr add 2404:e80:a137:191::1/64 dev lo nodad; ' + inner],
                       capture_output=True, text=True)
    out = r.stdout.split('AAAA')
    a = out[0].replace('A', '', 1).split()
    aaaa, rest = out[1].split('SANITY')
    aaaa = aaaa.split()
    sanity, bare = (x.split() for x in rest.split('BARE'))
    log = r.stdout + r.stderr
    lf.unlink()
    errs = [l for l in log.splitlines() if 'not giving name' in l or 'ignoring' in l.lower() or 'illegal' in l or 'fail' in l.lower()]
    print(f'{label:<38} A={a} AAAA={aaaa} lease-only={sanity} bare={bare}')
    if not a: print(log[-600:])
    if SHOWLOG:
        for l in log.splitlines():
            if ('au-plug-41' in l or 'Host ' in l) and 'query' not in l and ' config au' not in l and ' DHCP au' not in l: print('      |', l[l.find(']:')+2:])





run('today (x.iot dhcp-host, x.iot short)', auth=True)
run('fix A: bare dhcp-host + bare short', auth=True, dhcp_name='au-plug-41', short_name='au-plug-41')
run('fix A + v6 lease', auth=True, dhcp_name='au-plug-41', short_name='au-plug-41', v6lease=True)
run('fix B: --dhcp-fqdn, config unchanged', auth=True, fqdn_opt=True)
run('fix B + v6 lease', auth=True, fqdn_opt=True, v6lease=True)
