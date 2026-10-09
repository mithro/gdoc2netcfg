"""Issue #75: replay a real leaf (template DNS/DHCP options + real lease
file + a generated/ directory) in a private netns and query every name.
Usage: replay_leaf.py <net> <gw-v4> <gw-v6/len> <v4 cidr> <generated dir> <out.json>"""
import json, pathlib, re, shlex, subprocess, sys

net, gw4, gw6, cidr4, gendir, out = sys.argv[1:7]
here = pathlib.Path(__file__).parent.resolve()
skip = re.compile(r'^(interface|except-interface|listen-address|bind-dynamic|enable-ra|ra-param|'
                  r'server|enable-tftp|tftp-root|dhcp-boot|pxe-service|dhcp-broadcast|'
                  r'dhcp-option-force|log-facility|log-dhcp|dhcp-leasefile|conf-dir)\b')
opts = []
for f in sorted(pathlib.Path('/etc/dnsmasq.d/shared').glob('*.conf')) + \
         sorted(pathlib.Path(f'/etc/dnsmasq.d/{net}').glob('0*.conf')):
    for line in f.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and not skip.match(line):
            opts.append(line)
conf = here / f'replay-{net}.conf'
conf.write_text('\n'.join(opts) + '\n')
# Real leases, expiry pushed far ahead so none are pruned at load.
leases = here / f'replay-{net}.leases'
leases.write_text(''.join(re.sub(r'^\d+ ', '9999999999 ', l) for l in
                          open(f'/var/lib/misc/dnsmasq.{net}.leases')))
gen = pathlib.Path(gendir)
records = set()
for f in gen.glob('*.conf'):
    records |= set(re.findall(r'^host-record=([^,]+),', f.read_text(), re.M))
dom = re.search(r'^domain=([^,\s]+)', conf.read_text(), re.M).group(1)
lease_names = {l.split()[3] for l in leases.read_text().splitlines()
               if len(l.split()) > 3 and l.split()[3] != '*' and not l.startswith('duid')}
names = sorted(records | {f'{n}.{dom}' for n in lease_names} | lease_names)
qfile = here / f'replay-{net}.queries'
qfile.write_text(''.join(f'{n} {rr}\n' for n in names for rr in ('A', 'AAAA')))
args = ['/usr/sbin/dnsmasq', '--no-daemon', f'--conf-file={conf}', f'--conf-dir={gen}',
        '--pid-file', '--user=root', '--port=53', f'--listen-address={gw4}', '--bind-interfaces',
        '--log-facility=-', f'--dhcp-leasefile={leases}', '--dhcp-alternate-port=10067,10068']
sh = (f'ip link set lo up; ip addr add {cidr4} dev lo; ip addr add {gw6} dev lo nodad; '
      f'timeout 120 {shlex.join(args)} > {here}/replay-{net}.log 2>&1 & T=$!; sleep 1.5; '
      f'dig +noall +answer +time=2 +tries=1 @{gw4} -f {qfile}; kill $T; wait')
r = subprocess.run(['sudo', 'unshare', '-n', 'sh', '-c', sh], capture_output=True, text=True)
answers = {}
for line in r.stdout.splitlines():
    p = line.split()
    if len(p) >= 5 and p[3] in ('A', 'AAAA'):
        answers.setdefault(f'{p[0].rstrip(".")} {p[3]}', []).append(p[4])
log = (here / f'replay-{net}.log').read_text()
if 'started, version' not in log:
    raise SystemExit(f'dnsmasq did not start:\n{log[-1500:]}')
json.dump({'names': names, 'answers': answers}, open(out, 'w'), indent=1)
dups = sorted(k for k, v in answers.items() if len(v) != len(set(v)))
print(f'{net} {gendir}: {len(names)} names, {len(answers)} non-empty answers, {len(dups)} duplicated')
for f in (conf, leases, qfile):
    f.unlink()
