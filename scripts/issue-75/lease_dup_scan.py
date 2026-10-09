"""Issue #75 scope: for EVERY active DHCP lease on every leaf, query
<leasename>.<leafdomain> A/AAAA at that leaf and report duplicates,
classified by why (or why not) dnsmasq's lease/host-record dedup fired."""
import glob, re, subprocess, collections

def leaf_conf(leaf):
    text = ''.join(open(f).read() for f in glob.glob(f'/etc/dnsmasq.d/{leaf}/0*.conf'))
    gw = re.search(r'^listen-address=([\d.]+)', text, re.M)
    dom = re.search(r'^domain=([^,\s]+)', text, re.M)
    return (gw and gw.group(1)), (dom and dom.group(1))

for leaf in sorted(p.split('/')[3] for p in glob.glob('/etc/dnsmasq.d/*/generated')):
    gw, dom = leaf_conf(leaf)
    try:
        leases = [l.split() for l in open(f'/var/lib/misc/dnsmasq.{leaf}.leases')]
    except FileNotFoundError:
        continue
    names = {}
    for p in leases:
        if len(p) >= 4 and p[3] != '*' and p[0] != 'duid':
            names.setdefault(p[3].lower(), set()).add(p[2])
    if not names or not gw or not dom:
        print(f'{leaf}: leases={len(names)} gw={gw} domain={dom} (skipped)' if names else f'{leaf}: no named leases'); continue
    gen = ''.join(open(f).read() for f in glob.glob(f'/etc/dnsmasq.d/{leaf}/generated/*.conf'))
    recs = set(re.findall(r'^host-record=([^,]+),', gen, re.M))
    c = collections.Counter(); eg = collections.defaultdict(list)
    for n in sorted(names):
        fq = f'{n}.{dom}'
        dup = []
        for rr in ('A', 'AAAA'):
            out = subprocess.run(['dig', '+short', '+time=2', f'@{gw}', fq, rr], capture_output=True, text=True).stdout.split()
            if len(out) != len(set(out)): dup.append(rr)
        why = ('fqdn-rec' if fq in recs else 'no-fqdn-rec') + '/' + ('bare-rec' if n in recs else 'no-bare-rec')
        k = (why, 'DUP ' + '+'.join(dup) if dup else 'single')
        c[k] += 1
        if len(eg[k]) < 3: eg[k].append(n)
    print(f'{leaf} ({dom}) named leases={len(names)}')
    for k, v in sorted(c.items()): print(f'    {k[0]:<26} {k[1]:<12} {v:>3}  e.g. {", ".join(eg[k])}')
