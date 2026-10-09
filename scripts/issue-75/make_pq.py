"""Issue #75: build option P and option Q versions of real deployed leaf
files, so they can be compared with git diff --word-diff."""
import pathlib, re

HERE = pathlib.Path(__file__).parent
SRC = {'reterm2.conf': '/etc/dnsmasq.d/iot/generated/reterm2.conf',
       'au-plug-1.iot.conf': '/etc/dnsmasq.d/iot/generated/au-plug-1.iot.conf',
       'big-storage.conf': '/etc/dnsmasq.d/int/generated/big-storage.conf'}
BASE = {'reterm2.conf': 'reterm2', 'au-plug-1.iot.conf': 'au-plug-1', 'big-storage.conf': 'big-storage'}

for fname, src in SRC.items():
    text = ''.join(l for l in open(src) if not l.startswith(('dns-rr=', '# sshfp')))
    (HERE / 'today' / fname).write_text(text)
    base = BASE[fname]
    binds = re.findall(r'^dhcp-host=(.*)$', text, re.M)

    # P: every binding carries the host's base name; a bare host-record
    # with each binding's addresses must exist.
    p = re.sub(r'^(dhcp-host=.*,)[^,\n]+$', lambda m: m.group(1) + base, text, flags=re.M)
    for b in binds:
        f = b.split(',')
        v4 = next(x for x in f if re.fullmatch(r'[\d.]+', x))
        v6 = next(x.strip('[]') for x in f if x.startswith('['))
        rec = f'host-record={base},{v4},{v6}\n'
        if rec not in p:
            p = re.sub(r'(\n)(ptr-record=)', lambda m: '\n' + rec + '\n' + m.group(2), p, count=1) \
                if f'host-record={base},' not in p else p.replace(
                    [l for l in p.splitlines(True) if l.startswith(f'host-record={base},')][-1],
                    [l for l in p.splitlines(True) if l.startswith(f'host-record={base},')][-1] + rec)
    (HERE / 'P' / fname).write_text(p)

    # Q: bindings carry no name at all.
    (HERE / 'Q' / fname).write_text(re.sub(r'^(dhcp-host=.*),[^,\n\[\]]+$', r'\1', text, flags=re.M))

(HERE / 'Q' / '00-dhcp-names.conf').write_text('dhcp-ignore-names=tag:known\n')
